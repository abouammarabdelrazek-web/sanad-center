-- Sanad: allow therapists to create/update clinical assessments only for patients
-- in departments assigned to their account. Keep medical record deletion admin-only.
-- Applied to live Supabase project faqgsuicntypjrfggeol on 2026-11-01.

drop policy if exists patient_medical_records_select on public.patient_medical_records;
create policy patient_medical_records_select
on public.patient_medical_records
for select
to authenticated
using (
  public.is_admin()
  or exists (
    select 1 from public.patients p
    where p.id = patient_medical_records.patient_id
      and public.sanad_can_access_department(p.department_id)
  )
  or exists (
    select 1 from public.patient_departments pd
    where pd.patient_id = patient_medical_records.patient_id
      and public.sanad_can_access_department(pd.department_id)
  )
);

drop policy if exists patient_medical_records_insert on public.patient_medical_records;
create policy patient_medical_records_insert
on public.patient_medical_records
for insert
to authenticated
with check (
  updated_by = auth.uid()
  and (
    public.is_admin()
    or exists (
      select 1 from public.patients p
      where p.id = patient_medical_records.patient_id
        and public.sanad_can_access_department(p.department_id)
    )
    or exists (
      select 1 from public.patient_departments pd
      where pd.patient_id = patient_medical_records.patient_id
        and public.sanad_can_access_department(pd.department_id)
    )
  )
);

drop policy if exists patient_medical_records_update on public.patient_medical_records;
create policy patient_medical_records_update
on public.patient_medical_records
for update
to authenticated
using (
  public.is_admin()
  or exists (
    select 1 from public.patients p
    where p.id = patient_medical_records.patient_id
      and public.sanad_can_access_department(p.department_id)
  )
  or exists (
    select 1 from public.patient_departments pd
    where pd.patient_id = patient_medical_records.patient_id
      and public.sanad_can_access_department(pd.department_id)
  )
)
with check (
  updated_by = auth.uid()
  and (
    public.is_admin()
    or exists (
      select 1 from public.patients p
      where p.id = patient_medical_records.patient_id
        and public.sanad_can_access_department(p.department_id)
    )
    or exists (
      select 1 from public.patient_departments pd
      where pd.patient_id = patient_medical_records.patient_id
        and public.sanad_can_access_department(pd.department_id)
    )
  )
);
