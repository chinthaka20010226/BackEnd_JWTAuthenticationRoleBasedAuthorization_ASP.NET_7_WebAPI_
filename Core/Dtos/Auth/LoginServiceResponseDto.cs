namespace backend_dotnet7.Core.Dtos.Auth
{
    public class LoginServiceResponseDto
    {
        public string NewToken { get; set; }

        //This would be return to the front
        public UserInfoResult userInfo { get; set; }
    }
}
