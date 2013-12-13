create function TigGetDBProperty(_tkey varchar(255) CHARSET utf8) returns mediumtext CHARSET utf8
READS SQL DATA
begin
    declare _result mediumtext CHARSET utf8;

    select value into _result from variable_realm WHERE realm='extended_messaging' AND name=_tkey LIMIT 1;

    return (_result);
end