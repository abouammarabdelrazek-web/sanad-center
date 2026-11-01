alter table public.sanad_employees
  add column if not exists phone text;

create or replace function public.sanad_save_employee_with_departments(
  p_employee_id uuid,
  p_full_name text,
  p_job_title text,
  p_phone text,
  p_primary_department_id text,
  p_department_ids text[],
  p_is_active boolean,
  p_notes text default null
)
returns uuid
language plpgsql
set search_path to ''
as $function$
declare
  v_employee_id uuid;
  v_department_count integer;
  v_selected_count integer;
begin
  if auth.uid() is null or not public.is_admin() then
    raise exception 'غير مصرح بإدارة ملفات الموظفين';
  end if;

  if nullif(btrim(p_full_name), '') is null
     or nullif(btrim(p_job_title), '') is null
     or nullif(btrim(p_phone), '') is null then
    raise exception 'اسم الموظف والمسمى الوظيفي ورقم الهاتف مطلوبون';
  end if;

  if length(regexp_replace(btrim(p_phone), '[^0-9]', '', 'g')) < 10 then
    raise exception 'رقم الهاتف غير صحيح';
  end if;

  select count(distinct x) into v_selected_count
  from unnest(coalesce(p_department_ids, array[]::text[])) as x
  where nullif(btrim(x), '') is not null;

  if v_selected_count = 0 then
    raise exception 'يجب اختيار قسم واحد على الأقل للموظف';
  end if;

  if p_primary_department_id is not null
     and not (p_primary_department_id = any(coalesce(p_department_ids, array[]::text[]))) then
    raise exception 'القسم الأساسي يجب أن يكون ضمن الأقسام المختارة';
  end if;

  select count(*) into v_department_count
  from public.departments d
  where d.id = any(coalesce(p_department_ids, array[]::text[]));

  if v_department_count <> v_selected_count then
    raise exception 'يوجد قسم غير صحيح ضمن الاختيارات';
  end if;

  if p_employee_id is null then
    insert into public.sanad_employees
      (full_name, job_title, phone, primary_department_id, is_active, notes, created_by)
    values
      (btrim(p_full_name), btrim(p_job_title), btrim(p_phone), p_primary_department_id,
       coalesce(p_is_active, true), nullif(btrim(p_notes), ''), auth.uid())
    returning id into v_employee_id;
  else
    update public.sanad_employees
    set full_name = btrim(p_full_name),
        job_title = btrim(p_job_title),
        phone = btrim(p_phone),
        primary_department_id = p_primary_department_id,
        is_active = coalesce(p_is_active, true),
        notes = nullif(btrim(p_notes), ''),
        updated_at = now()
    where id = p_employee_id
    returning id into v_employee_id;

    if v_employee_id is null then
      raise exception 'ملف الموظف المطلوب تعديله غير موجود';
    end if;
  end if;

  delete from public.sanad_employee_departments
  where employee_id = v_employee_id;

  insert into public.sanad_employee_departments (employee_id, department_id)
  select v_employee_id, x
  from (
    select distinct btrim(u.department_id) as x
    from unnest(coalesce(p_department_ids, array[]::text[])) as u(department_id)
    where nullif(btrim(u.department_id), '') is not null
  ) selected;

  return v_employee_id;
end;
$function$;

revoke all on function public.sanad_save_employee_with_departments(uuid,text,text,text,text,text[],boolean,text) from public, anon;
grant execute on function public.sanad_save_employee_with_departments(uuid,text,text,text,text,text[],boolean,text) to authenticated;
