-- Sanad: allow therapists to read their own completed sessions and save only
-- the three clinical-note fields through a role-checked RPC.
-- Applied to live Supabase project faqgsuicntypjrfggeol on 2026-11-01.

drop policy if exists therapy_sessions_select on public.therapy_sessions;
create policy therapy_sessions_select
on public.therapy_sessions
for select
to authenticated
using (
  public.is_admin()
  or public.can_manage_department(department_id)
  or (
    public.sanad_user_role() = 'therapist'::text
    and therapist_id = auth.uid()
    and public.sanad_can_access_department(department_id)
  )
);

create or replace function public.sanad_update_therapy_session_notes(
  p_session_id uuid,
  p_treatment_provided text,
  p_patient_response text,
  p_home_program text
)
returns void
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_department_id text;
  v_therapist_id uuid;
  v_voided_at timestamptz;
  v_role text;
begin
  if auth.uid() is null then
    raise exception 'يجب تسجيل الدخول';
  end if;

  select ts.department_id,ts.therapist_id,ts.voided_at
  into v_department_id,v_therapist_id,v_voided_at
  from public.therapy_sessions ts
  where ts.id=p_session_id
  for update;

  if not found then
    raise exception 'الجلسة غير موجودة';
  end if;
  if v_voided_at is not null then
    raise exception 'لا يمكن تعديل تفاصيل جلسة تم عكسها';
  end if;

  v_role := public.sanad_user_role();
  if not (
    v_role = 'admin'
    or (v_role = 'technical_manager' and public.can_manage_department(v_department_id))
    or (
      v_role = 'therapist'
      and v_therapist_id = auth.uid()
      and public.sanad_can_access_department(v_department_id)
    )
  ) then
    raise exception 'لا تملك صلاحية تعديل تفاصيل هذه الجلسة';
  end if;

  update public.therapy_sessions
  set treatment_provided = p_treatment_provided,
      patient_response = p_patient_response,
      home_program = p_home_program
  where id=p_session_id;
end;
$function$;

revoke all on function public.sanad_update_therapy_session_notes(uuid,text,text,text) from public;
revoke all on function public.sanad_update_therapy_session_notes(uuid,text,text,text) from anon;
grant execute on function public.sanad_update_therapy_session_notes(uuid,text,text,text) to authenticated;
