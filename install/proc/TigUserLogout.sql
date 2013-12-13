create procedure TigUserLogout(_user_id varchar(2049) CHARSET utf8)
begin
    DECLARE _uid varchar(2049) CHARSET utf8 DEFAULT TigLocalpartFromJID(_user_id);
    IF _uid REGEXP '^[0-9]+$' 
    THEN
        update extended_messaging_sessions set online = greatest(online - 1, 0) where uid = _uid;
     end if;  
end