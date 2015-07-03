CREATE PROCEDURE `TigUserLogin`(_user_id varchar(255) CHARSET utf8, _user_token varchar(255) CHARSET utf8)
begin
    DECLARE _uid INT DEFAULT 0;
    DECLARE _result varchar(255) CHARSET utf8 DEFAULT null;

    SET _uid = TigLocalpartFromJID(_user_id);
    if LEFT(_user_token, 6) = 'TOKEN|'
    then
        if exists(select 1 from extended_messaging_sessions
            where (created > UNIX_TIMESTAMP()-84600) AND (_uid = uid) AND (token = SUBSTRING(_user_token,7)))
        then
            SET _result = _user_id;
        end if;
    else
        if exists(select 1 from users
            where (status > 0) AND (_uid = uid) AND (pass = MD5(_user_token)))
        then
            SET _result = _user_id;
        end if;
    end if;

    if NOT ISNULL(_result) AND _uid>0
    then
        update extended_messaging_sessions
                set online = online + 1
                where uid = _uid;
    end if;
    select _result as user_id;
end
