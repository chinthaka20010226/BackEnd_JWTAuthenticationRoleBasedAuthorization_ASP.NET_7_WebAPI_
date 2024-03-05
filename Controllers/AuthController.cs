using backend_dotnet7.Core.Constants;
using backend_dotnet7.Core.Dtos.Auth;
using backend_dotnet7.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections;

namespace backend_dotnet7.Controllers
{
    public class AuthController : Controller
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // Route -> Seed role to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedResult = await _authService.SeedRolesAsync();
            return StatusCode(seedResult.StatusCode, seedResult.Message);
        }

        // Route -> Register
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var registerResult = await _authService.RegisterAsync(registerDto);
            return StatusCode(registerResult.StatusCode, registerResult.Message);
        }

        // Route -> Login
        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult<LoginServiceResponseDto>> Login([FromBody] LoginDto loginDto)
        {
            var loginResult = await _authService.LoginAsync(loginDto);

            if (loginResult is null)
            {
                return Unauthorized("Your credentials are invalid. Please contact to an Admin");
            }

            return Ok(loginResult);
        }

        // Route -> Update User Role
        // Admin can change User Role
        [HttpPost]
        [Route("update-role")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public async Task<IActionResult> UpdateRole([FromBody] UpdateRoleDto updateRoleDto)
        {
            var updateRoleResult = await _authService.UpdateRoleAsync(User, updateRoleDto);

            if (updateRoleResult.IsSucceed)
            {
                return Ok(updateRoleResult.Message);
            }
            else
            {
                return StatusCode(updateRoleResult.StatusCode, updateRoleResult.Message);
            }
        }

        // Route -> getting data of a user from it's JWT
        [HttpPost]
        [Route("me")]
        public async Task<ActionResult<LoginServiceResponseDto>> Me([FromBody] MeDto token)
        {
            try
            {
                var me = await _authService.MeAsync(token);
                if(me is not null)
                {
                    return Ok(me);
                }
                else
                {
                    return Unauthorized("Invalid Token");
                }
            }
            catch(Exception ex)
            {
                return Unauthorized("Invalid Token");
            }
        }

        // Route -> List of all Users with details
        [HttpGet]
        [Route("users")]
        public async Task<ActionResult<IEnumerable<UserInfoResult>>> GetUsersList()
        {
            var usersList = await _authService.GetUsersListAsync();
            return Ok(usersList);
        }

        // Route -> Get a User by UserName
        [HttpGet]
        [Route("users/{userName}")] //[Route("users/{parameter}")]
        public async Task<ActionResult<UserInfoResult>> GetUserDetailsByUserName([FromRoute] string userName)
        {
            var user = await _authService.GetUserDetailsByUserNameAsync(userName);
            if (user is not null)
            {
                return Ok(user);
            }
            else
            {
                return NotFound("UserName not found");
            }
        }

        // Route -> Get List of all usernames for send message
        [HttpGet]
        [Route("usernames")]
        public async Task<ActionResult<IEnumerable<string>>> GetUserNamesList()
        {
            var userNames = await _authService.GetUsernameListAsync();
            return Ok(userNames);
        }

    }
}
