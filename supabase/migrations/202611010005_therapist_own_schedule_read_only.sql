-- Sanad: therapists can read only appointments assigned to their own account.
-- Technical managers can read all appointments in their assigned departments.
-- Admin/secretary retain full schedule visibility. Existing INSERT/UPDATE policies
-- remain restricted to admin/secretary (plus admin-only DELETE).
-- Applied to live project faqgsuicntypjrfggeol on 2026-11-01.

drop policy if exists sanad_calendar_select on public.sanad_calendar_appointments;
create policy sanad_calendar_select
on public.sanad_calendar_appointments
for select
to authenticated
using (
  public.sanad_is_admin_or_secretary()
  or (
    public.sanad_user_role() = 'technical_manager'::text
    and public.sanad_can_access_department(department_id)
  )
  or (
    public.sanad_user_role() = 'therapist'::text
    and therapist_id = auth.uid()
    and public.sanad_can_access_department(department_id)
  )
);
