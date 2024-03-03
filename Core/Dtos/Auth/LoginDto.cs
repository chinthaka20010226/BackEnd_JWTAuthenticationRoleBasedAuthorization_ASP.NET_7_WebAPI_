using System.ComponentModel.DataAnnotations;

namespace backend_dotnet7.Core.Dtos.Auth
{
    public class LoginDto
    {
        [Required(ErrorMessage = "UserName is Required")] //validation part in backend
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is Required")] //validation part in backend
        public string Password { get; set; }
    }
}
