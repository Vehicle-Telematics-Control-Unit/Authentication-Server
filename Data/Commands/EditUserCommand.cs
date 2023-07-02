namespace AuthenticationServer.Data.Commands
{
    public class EditUserCommand
    {
        
        public string? NewPassword { get; set; }
        public string? Password { get; set; }

        
        public EditUserCommand() { }
    }
}
