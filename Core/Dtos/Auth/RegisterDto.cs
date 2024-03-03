using System.ComponentModel.DataAnnotations;

namespace backend_dotnet7.Core.Dtos.Auth
{
    public class RegisterDto
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }

        [Required(ErrorMessage = "UserName is Required")] //validation part in backend
        public string Username { get; set; }

        public string Email { get; set; }

        [Required(ErrorMessage = "Password is Required")] //validation part in backend
        public string Password { get; set; }

        public string Address { get; set; }
    }
}
