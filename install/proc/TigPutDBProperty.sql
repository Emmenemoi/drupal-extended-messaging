create procedure TigPutDBProperty(_tkey varchar(255) CHARSET utf8, _tval mediumtext CHARSET utf8)
begin
      insert into variable_realm (name, realm, value, serialized) VALUES (_tkey, 'extended_messaging', _tval, 0) ON DUPLICATE KEY UPDATE value=_tval;
end