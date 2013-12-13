create procedure TigUserLoginPlainPw(_user_id varchar(2049) CHARSET utf8, _user_pw varchar(255) CHARSET utf8)
begin
    case TigGetDBProperty('password-encoding')
        when 'MD5-PASSWORD' then
            call TigUserLogin(_user_id, MD5(_user_pw));
        when 'MD5-USERID-PASSWORD' then
            call TigUserLogin(_user_id, MD5(CONCAT(_user_id, _user_pw)));
        when 'MD5-USERNAME-PASSWORD' then
            call TigUserLogin(_user_id, MD5(CONCAT(substring_index(_user_id, '@', 1), _user_pw)));
        else
            call TigUserLogin(_user_id, _user_pw);
        end case;
end