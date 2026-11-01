create or replace function private.sanad_list_schedule_therapists_with_phone_internal()
returns table(employee_id uuid, phone text)
language plpgsql
stable
security definer
set search_path to ''
as $function$
declare
  v_role text;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  v_role := public.sanad_user_role();
  if v_role not in ('admin', 'secretary', 'receptionist') then
    raise exception 'Not authorized to view therapist contact details';
  end if;

  return query
  select e.id, e.phone
  from public.sanad_employees e
  where e.is_active = true;
end;
$function$;

revoke all on function private.sanad_list_schedule_therapists_with_phone_internal() from public, anon;
grant execute on function private.sanad_list_schedule_therapists_with_phone_internal() to authenticated;

create or replace function public.sanad_list_schedule_therapists_with_phone()
returns table(employee_id uuid, phone text)
language sql
stable
set search_path to ''
as $function$
  select * from private.sanad_list_schedule_therapists_with_phone_internal();
$function$;

revoke all on function public.sanad_list_schedule_therapists_with_phone() from public, anon;
grant execute on function public.sanad_list_schedule_therapists_with_phone() to authenticated;
