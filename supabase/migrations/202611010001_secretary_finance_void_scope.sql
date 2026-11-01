-- Sanad Center security patch: secretary finance scope
-- Project: faqgsuicntypjrfggeol
-- Applied to the live database on 2026-11-01.
-- Restrict direct treasury-account reads to admin/accountant.
drop policy if exists treasury_accounts_select on public.treasury_accounts;
create policy treasury_accounts_select
on public.treasury_accounts
for select
to authenticated
using (public.sanad_user_role() = any (array['admin'::text, 'accountant'::text]));

-- Secretaries may void ordinary financial entries only for Cairo's current day.
-- The only exception is the atomic completed-session reversal flow when a
-- matching refund-proof record exists and the full session collection is being reversed.
CREATE OR REPLACE FUNCTION public.sanad_void_financial_entry(p_entry_id uuid, p_reason text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_role text;
  v_original public.financial_entries%rowtype;
  v_new_id uuid;
  v_appointment public.sanad_calendar_appointments%rowtype;
  v_allocation public.patient_account_payment_allocations%rowtype;
  v_receipt public.patient_account_receipts%rowtype;
  v_appointment_collected numeric(12,2);
begin
  v_role := public.sanad_user_role();

  if auth.uid() is null or v_role is distinct from 'admin' and v_role is distinct from 'secretary' then
    raise exception 'إلغاء الحركة المالية متاح للمدير الإداري والسكرتارية فقط';
  end if;
  if p_reason is null or length(trim(p_reason)) < 3 then
    raise exception 'اكتب سببًا واضحًا لإلغاء الحركة';
  end if;

  select * into v_original
  from public.financial_entries
  where id = p_entry_id
  for update;
  if not found then raise exception 'الحركة المالية غير موجودة'; end if;

  -- Secretaries may void ordinary entries only for Cairo's current day.
  -- Older entries can be reversed only as part of the protected completed-session
  -- refund flow, which inserts its refund proof and reverses all linked allocations
  -- atomically in the same transaction.
  if v_role = 'secretary'
     and (v_original.entry_date at time zone 'Africa/Cairo')::date
         <> (now() at time zone 'Africa/Cairo')::date
     and not exists (
       select 1
       from public.patient_session_refunds r
       join public.patient_account_charges c
         on c.calendar_appointment_id = r.appointment_id
        and c.voided_at is null
       join public.patient_account_payment_allocations a
         on a.charge_id = c.id
        and a.financial_entry_id = p_entry_id
        and a.voided_at is null
       where r.appointment_id = v_original.calendar_appointment_id
         and r.created_by = auth.uid()
         and r.amount = (
           select coalesce(sum(a2.amount),0)::numeric(12,2)
           from public.patient_account_payment_allocations a2
           join public.patient_account_charges c2 on c2.id = a2.charge_id
           where c2.calendar_appointment_id = r.appointment_id
             and c2.voided_at is null
         )
     ) then
    raise exception 'يمكن للسكرتارية إلغاء حركات اليوم فقط؛ التراجع عن جلسة قديمة يتطلب إجراء رد المبلغ المعتمد';
  end if;

  if v_original.category = 'package_payment' then
    raise exception 'هذه دفعة باقة. لا يمكن إلغاؤها من زر الحركات العادية؛ يلزم إجراء استرداد باقة يحافظ على رصيد الجلسات وسجل الدفعات';
  end if;
  if v_original.reversal_of is not null or v_original.category = 'accounting_reversal' then
    raise exception 'لا يمكن إلغاء قيد عكسي';
  end if;
  if exists (select 1 from public.financial_entries where reversal_of = p_entry_id) then
    raise exception 'تم إلغاء هذه الحركة من قبل';
  end if;

  select * into v_allocation
  from public.patient_account_payment_allocations
  where financial_entry_id = p_entry_id and voided_at is null
  for update;

  if found then
    update public.patient_account_payment_allocations
    set voided_at = now(),
        voided_by = auth.uid(),
        void_reason = btrim(p_reason)
    where id = v_allocation.id;

    select * into v_receipt
    from public.patient_account_receipts
    where id = v_allocation.receipt_id
    for update;

    if v_receipt.calendar_appointment_id is not null then
      select coalesce(sum(a.amount),0)::numeric(12,2)
      into v_appointment_collected
      from public.patient_account_payment_allocations a
      join public.patient_account_charges c on c.id=a.charge_id
      where a.receipt_id=v_receipt.id
        and a.voided_at is null
        and c.voided_at is null
        and c.calendar_appointment_id=v_receipt.calendar_appointment_id;

      select * into v_appointment
      from public.sanad_calendar_appointments
      where id = v_receipt.calendar_appointment_id
      for update;

      if found and v_appointment.status = 'completed' then
        perform pg_catalog.set_config('sanad.reverse_appointment_id',v_appointment.id::text,true);
        update public.sanad_calendar_appointments
        set collected_amount = v_appointment_collected,
            payment_method = case when v_appointment_collected > 0 then v_receipt.payment_method else null end,
            updated_at = now()
        where id = v_appointment.id;
        perform pg_catalog.set_config('sanad.reverse_appointment_id','',true);
      end if;
    end if;
  elsif v_original.calendar_appointment_id is not null then
    select * into v_appointment
    from public.sanad_calendar_appointments
    where id = v_original.calendar_appointment_id
    for update;
    if not found then raise exception 'الموعد المرتبط بالحركة غير موجود'; end if;
    if v_appointment.package_id is not null then
      raise exception 'لا يمكن إلغاء تحصيل مرتبط بباقة من هذا الإجراء';
    end if;
    if v_appointment.status <> 'completed' then
      raise exception 'حالة الموعد لا تسمح بتصحيح التحصيل من هذا الإجراء';
    end if;

    perform pg_catalog.set_config('sanad.reverse_appointment_id',v_appointment.id::text,true);
    update public.sanad_calendar_appointments
    set collected_amount = 0,
        payment_method = null,
        updated_at = now()
    where id = v_appointment.id;
    perform pg_catalog.set_config('sanad.reverse_appointment_id','',true);
  end if;

  insert into public.financial_entries (
    entry_type,amount,department_id,category,description,
    entry_date,payment_method,reference_number,created_by,reversal_of,patient_id
  )
  values (
    case when v_original.entry_type = 'income' then 'expense' else 'income' end,
    v_original.amount,
    v_original.department_id,
    'accounting_reversal',
    'إلغاء الحركة رقم ' || p_entry_id::text || ' - السبب: ' || trim(p_reason),
    now(),
    v_original.payment_method,
    v_original.reference_number,
    auth.uid(),
    p_entry_id,
    v_original.patient_id
  )
  returning id into v_new_id;

  return v_new_id;
end;
$function$

