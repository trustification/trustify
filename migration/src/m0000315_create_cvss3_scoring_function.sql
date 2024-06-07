
-- Calcuate a CVSS3 score from an *entire* row of the `cvss3` table
create or replace function cvss3_score(cvss3_p cvss3)
    returns real
as
$$
declare
    exploitability decimal;
    iss decimal;
    iss_scoped decimal;
    score decimal;
begin
    if cvss3_p is null then
        return null;
    end if;

    exploitability := cvss3_exploitability(cvss3_p);
    iss = cvss3_impact( cvss3_p );

    if not(cvss3_scope_changed( cvss3_p.s)) then
        iss_scoped := 6.42 * iss;
    else
        iss_scoped := (7.52 * (iss - 0.029)) - pow(3.25 * (iss - 0.02), 15.0);
    end if;

    if iss_scoped <= 0.0 then
        score := 0.0;
    elsif not(cvss3_scope_changed( cvss3_p.s)) then
        score := least(iss_scoped + exploitability, 10.0);
    else
        score := least(1.08 * (iss_scoped + exploitability), 10.0);
    end if;

    return score;
end
$$
    language 'plpgsql';


create or replace function cvss3_exploitability(cvss3_p cvss3)
    returns real
as
$$
declare
    av_score decimal;
    ac_score decimal;
    ui_score decimal;
    pr_score decimal;
    scope_changed bool;
begin
    scope_changed = cvss3_scope_changed(cvss3_p.s);

    av_score := cvss3_av_score(cvss3_p.av);
    ac_score := cvss3_ac_score(cvss3_p.ac);
    ui_score := cvss3_ui_score(cvss3_p.ui);
    pr_score := cvss3_pr_scoped_score(cvss3_p.pr, scope_changed);


    return (8.22 * av_score * ac_score * pr_score * ui_score);
end;
$$
    language 'plpgsql';



create or replace function cvss3_impact(cvss3_p cvss3)
    returns real
as
$$
declare
    c_score decimal;
    i_score decimal;
    a_score decimal;
begin
    c_score := cvss3_c_score(cvss3_p.c);
    i_score := cvss3_i_score(cvss3_p.i);
    a_score := cvss3_a_score(cvss3_p.a);

    return (1.0 - abs((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score)));
end;
$$
    language 'plpgsql';


create or replace function cvss3_av_score(av_p cvss3_av)
    returns real
as
$$
begin
    if av_p = 'p'::cvss3_av then
        return 0.20;
    elsif av_p = 'l'::cvss3_av then
        return 0.55;
    elsif av_p = 'a'::cvss3_av then
        return 0.62;
    elsif av_p = 'n'::cvss3_av then
        return 0.85;
    end if;

    return 0.0;

end;
$$
    language 'plpgsql';


create or replace function cvss3_ac_score(ac_p cvss3_ac)
    returns real
as
$$
begin
    if ac_p = 'h'::cvss3_ac then
        return 0.44;
    elsif ac_p = 'l'::cvss3_ac then
        return 0.77;
    end if;

    return 0.0;

end;
$$
    language 'plpgsql';





create or replace function cvss3_pr_scoped_score(pr_p cvss3_pr, scope_changed_p bool)
    returns real
as
$$
begin
    if pr_p = 'h'::cvss3_pr then
        if scope_changed_p then
            return 0.50;
        else
            return 0.27;
        end if;
    elsif pr_p = 'l'::cvss3_pr then
        if scope_changed_p then
            return 0.68;
        else
            return 0.62;
        end if;
    end if;

    return 0.85;

end;
$$
    language 'plpgsql';

create or replace function cvss3_ui_score(ui_p cvss3_ui)
    returns real
as
$$
begin
    if ui_p = 'r'::cvss3_ui then
        return 0.62;
    end if;

    return 0.85;

end;
$$
    language 'plpgsql';

create or replace function cvss3_scope_changed(s_p cvss3_s)
    returns bool
as
$$
begin
    return s_p = 'c'::cvss3_s;

end;
$$
    language 'plpgsql';

create or replace function cvss3_c_score(c_p cvss3_c)
    returns real
as
$$
begin
    if c_p = 'n'::cvss3_c then
        return 0.0;
    elsif c_p = 'l'::cvss3_c then
        return 0.22;
    elsif c_p = 'h'::cvss3_c then
        return 0.56;
    end if;

    return 0.85;

end;
$$
    language 'plpgsql';

create or replace function cvss3_i_score(i_p cvss3_i)
    returns real
as
$$
begin
    if i_p = 'n'::cvss3_i then
        return 0.0;
    elsif i_p = 'l'::cvss3_i then
        return 0.22;
    elsif i_p = 'h'::cvss3_i then
        return 0.56;
    end if;

    return 0.85;

end;
$$
    language 'plpgsql';

create or replace function cvss3_a_score(a_p cvss3_a)
    returns real
as
$$
begin
    if a_p = 'n'::cvss3_a then
        return 0.0;
    elsif a_p = 'l'::cvss3_a then
        return 0.22;
    elsif a_p = 'h'::cvss3_a then
        return 0.56;
    end if;

    return 0.85;

end;
$$
    language 'plpgsql';
