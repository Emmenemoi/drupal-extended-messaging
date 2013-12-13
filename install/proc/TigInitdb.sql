   create procedure TigInitdb()
   begin
   update extended_messaging_sessions set online = 0;
   end