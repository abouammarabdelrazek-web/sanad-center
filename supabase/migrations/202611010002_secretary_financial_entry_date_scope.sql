-- Sanad: restrict secretary-entered financial dates to Cairo's current day.
-- Applied to live Supabase project faqgsuicntypjrfggeol on 2026-11-01.

drop policy if exists financial_entries_insert on public.financial_entries;
create policy financial_entries_insert
on public.financial_entries
for insert
to authenticated
with check (
  public.sanad_user_role() = any (array['admin'::text, 'accountant'::text])
  or (
    public.sanad_user_role() = 'secretary'::text
    and (entry_date at time zone 'Africa/Cairo')::date
        = (now() at time zone 'Africa/Cairo')::date
  )
);

-- The SECURITY DEFINER payment helper bypasses table RLS, so enforce the
-- same secretary date rule inside the helper itself.
create or replace function public.sanad_apply_patient_payment(
  p_patient_id uuid,
  p_amount numeric,
  p_payment_method text,
  p_payment_date timestamp with time zone,
  p_notes text,
  p_calendar_appointment_id uuid default null::uuid
)
returns uuid
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_receipt_id uuid;
  v_charge record;
  v_paid numeric(12,2);
  v_due numeric(12,2);
  v_allocate numeric(12,2);
  v_remaining numeric(12,2);
  v_financial_entry_id uuid;
  v_category text;
begin
  if auth.uid() is null or not public.sanad_is_admin_or_secretary() then
    raise exception 'تحصيل حساب المريض متاح للمدير الإداري والسكرتارية فقط';
  end if;
  if public.sanad_user_role() = 'secretary'::text
     and (coalesce(p_payment_date, now()) at time zone 'Africa/Cairo')::date
         <> (now() at time zone 'Africa/Cairo')::date then
    raise exception 'يمكن للسكرتارية تسجيل التحصيل بتاريخ اليوم فقط';
  end if;
  if p_amount is null or p_amount <= 0 then
    raise exception 'مبلغ التحصيل يجب أن يكون أكبر من صفر';
  end if;
  if p_payment_method is null or p_payment_method not in ('cash','card','transfer','other') then
    raise exception 'طريقة الدفع غير صحيحة';
  end if;

  perform 1 from public.patients where id=p_patient_id for update;
  if not found then raise exception 'المريض غير موجود'; end if;

  insert into public.patient_account_receipts (
    patient_id,calendar_appointment_id,amount,payment_method,payment_date,notes,created_by
  )
  values (
    p_patient_id,p_calendar_appointment_id,p_amount,p_payment_method,
    coalesce(p_payment_date,now()),nullif(btrim(coalesce(p_notes,'')),''),
    auth.uid()
  )
  returning id into v_receipt_id;

  v_remaining := p_amount;

  for v_charge in
    select c.id,c.amount,c.department_id,c.calendar_appointment_id
    from public.patient_account_charges c
    join public.therapy_sessions ts
      on ts.id=c.therapy_session_id and ts.voided_at is null
    where c.patient_id=p_patient_id and c.voided_at is null
    order by ts.session_date,c.charge_date,c.id
    for update of c
  loop
    exit when v_remaining <= 0;

    select coalesce(sum(a.amount),0)::numeric(12,2)
    into v_paid
    from public.patient_account_payment_allocations a
    where a.charge_id=v_charge.id and a.voided_at is null;

    v_due := greatest(v_charge.amount-v_paid,0);
    if v_due <= 0 then continue; end if;

    v_allocate := least(v_due,v_remaining);
    v_category := case
      when p_calendar_appointment_id is not null
       and v_charge.calendar_appointment_id = p_calendar_appointment_id
      then 'patient_session_payment'
      else 'patient_debt_payment'
    end;

    insert into public.financial_entries (
      entry_type,amount,department_id,category,description,entry_date,
      payment_method,reference_number,created_by,patient_id
    )
    values (
      'income',v_allocate,v_charge.department_id,v_category,
      'تحصيل من حساب المريض — استحقاق موعد '
        || v_charge.calendar_appointment_id::text,
      coalesce(p_payment_date,now()),p_payment_method,
      'PATIENT-RECEIPT-' || v_receipt_id::text,auth.uid(),p_patient_id
    )
    returning id into v_financial_entry_id;

    insert into public.patient_account_payment_allocations (
      receipt_id,charge_id,financial_entry_id,amount,created_by
    )
    values (
      v_receipt_id,v_charge.id,v_financial_entry_id,v_allocate,auth.uid()
    );

    v_remaining := v_remaining-v_allocate;
  end loop;

  if v_remaining > 0 then
    raise exception 'مبلغ التحصيل أكبر من إجمالي المديونية المستحقة. المبلغ الزائد: %',
      v_remaining;
  end if;

  return v_receipt_id;
end;
$function$;
