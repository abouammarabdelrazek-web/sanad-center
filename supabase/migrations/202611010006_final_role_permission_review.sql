-- Close authorization gaps found during the final role-permission review.
-- Keep this migration in sync with the already-verified live database changes.

create or replace function public.sanad_record_package_payment()
returns trigger
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_patient_id uuid;
  v_department_id text;
  v_financial_entry_id uuid;
  v_role text;
begin
  v_role := public.sanad_user_role();

  if auth.uid() is null
     or v_role is distinct from 'admin'
        and v_role is distinct from 'secretary' then
    raise exception 'تسجيل دفعات الباقات متاح للمدير الإداري والسكرتارية فقط';
  end if;

  if new.created_by is distinct from auth.uid() then
    raise exception 'منشئ الدفعة يجب أن يكون المستخدم الحالي';
  end if;

  -- The trigger is SECURITY DEFINER and therefore must enforce the
  -- secretary's same-day restriction itself instead of relying on RLS.
  if v_role = 'secretary'
     and (new.payment_date at time zone 'Africa/Cairo')::date
         <> (now() at time zone 'Africa/Cairo')::date then
    raise exception 'السكرتارية تسجل دفعات الباقات بتاريخ اليوم فقط';
  end if;

  select pp.patient_id, pp.department_id
    into v_patient_id, v_department_id
  from public.patient_packages pp
  where pp.id = new.package_id;

  if not found then raise exception 'Package not found'; end if;
  if new.patient_id <> v_patient_id or new.department_id <> v_department_id then
    raise exception 'Payment patient or department does not match package';
  end if;

  insert into public.financial_entries (
    entry_type,amount,department_id,category,description,entry_date,
    payment_method,reference_number,created_by,patient_id
  )
  values (
    'income',new.amount,new.department_id,'package_payment',
    'تحصيل دفعة باقة علاجية - رقم الباقة: '||new.package_id::text,
    new.payment_date,new.payment_method,new.reference_number,new.created_by,new.patient_id
  )
  returning id into v_financial_entry_id;

  update public.package_payments
  set financial_entry_id=v_financial_entry_id
  where id=new.id;

  return new;
end;
$function$;

drop policy if exists appointments_select_by_role on public.appointments;
create policy appointments_select_by_role
on public.appointments
for select
to authenticated
using (
  (select public.sanad_is_admin_or_secretary())
  or (
    (select public.sanad_user_role()) = 'technical_manager'
    and (select public.sanad_can_access_department(appointments.department_id))
  )
  or (
    (select public.sanad_user_role()) = 'therapist'
    and appointments.therapist_id = (select auth.uid())
    and (select public.sanad_can_access_department(appointments.department_id))
  )
);
