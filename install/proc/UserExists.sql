CREATE PROCEDURE `UserExists`(_user_id varchar(255) CHARSET utf8)
begin
    DECLARE _uid INT DEFAULT 0;
    DECLARE _result varchar(255) CHARSET utf8 DEFAULT null;

    SET _uid = TigLocalpartFromJID(_user_id);
    if exists(select 1 from users
        where (status > 0) AND (_uid = uid))
    then
        SET _result = _user_id;
    end if;

    select _result as user_id;
end
