using backend_dotnet7.Core.Constants;
using backend_dotnet7.Core.Dtos.Auth;
using backend_dotnet7.Core.Dtos.General;
using backend_dotnet7.Core.Entities;
using backend_dotnet7.Core.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace backend_dotnet7.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogService _logService;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,ILogService logService, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logService = logService;
            _configuration = configuration;
        }

        public async Task<GeneralServiceResponseDto> SeedRolesAsync()
        {
            //bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            //bool isManagerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.MANAGER);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isAdminRoleExists && isUserRoleExists)
                return new GeneralServiceResponseDto()
                {
                    IsSucceed = true,
                    StatusCode = 200,
                    Message = "Roles Seeding is Already Done"
                };

            //await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            //await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.MANAGER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));

            return new GeneralServiceResponseDto()
            {
                IsSucceed = true,
                StatusCode = 201,
                Message = "Roles Seeding Done Successfully"
            };
        }

        public async Task<GeneralServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isExistsUser = await _userManager.FindByNameAsync(registerDto.Username);

            if (isExistsUser is not null)
                return new GeneralServiceResponseDto()
                {
                    IsSucceed = false,
                    StatusCode = 409,
                    Message = "UserName Alredy Exists"
                };

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                Email = registerDto.Email,
                UserName = registerDto.Username,
                Address = registerDto.Address,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var createUserResult = await _userManager.CreateAsync(newUser,registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation failed because : ";
                foreach(var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }

                return new GeneralServiceResponseDto()
                {
                    IsSucceed = false,
                    StatusCode = 400,
                    Message = "errorString"
                };
            }

            //Add a Default User Role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);
            await _logService.SaveNewLog(newUser.UserName, "Registered to Website");

            return new GeneralServiceResponseDto()
            {
                IsSucceed = true,
                StatusCode = 201,
                Message = "User"
            };

        }

        public async Task<LoginServiceResponseDto?> LoginAsync(LoginDto loginDto)
        {
            //Find user with username
            var user = await _userManager.FindByNameAsync(loginDto.Username);

            if (user is null)
            {
                return null;
            }

            //Check password of user
            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordCorrect)
            {
                return null;
            }

            //Return Token and userInfo to front-end
            var NewToken = await GenerateJWTTokenAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var userInfo = GenerateUserInfoObject(user, roles);
            await _logService.SaveNewLog(user.UserName, "New Login");

            return new LoginServiceResponseDto()
            {
                NewToken = NewToken,
                userInfo = userInfo
            };


        }

        public async Task<GeneralServiceResponseDto> UpdateRoleAsync(ClaimsPrincipal User, UpdateRoleDto updateRoleDto)
        {
            var user = await _userManager.FindByNameAsync(updateRoleDto.UserName);
            if(user is null)
            {
                return new GeneralServiceResponseDto()
                {
                    IsSucceed = false,
                    StatusCode = 404,
                    Message = "User Invalid"
                };

            }

            var userRoles = await _userManager.GetRolesAsync(user);

            //Just the Admin can updated the Role
            if (User.IsInRole(StaticUserRoles.ADMIN))
            {
                //User is admin
                if(updateRoleDto.NewRole == RoleType.USER)
                {
                    //admin can change the role of users
                    if(userRoles.Any(q => q.Equals(StaticUserRoles.ADMIN)))
                    {
                        return new GeneralServiceResponseDto()
                        {
                            IsSucceed = false,
                            StatusCode = 403,
                            Message = "You are not to change role of this user"
                        };
                    }
                    else
                    {
                        await _userManager.RemoveFromRolesAsync(user, userRoles);
                        await _userManager.AddToRoleAsync(user, updateRoleDto.NewRole.ToString());
                        await _logService.SaveNewLog(user.UserName, "User Roles Upated");

                        return new GeneralServiceResponseDto()
                        {
                            IsSucceed = true,
                            StatusCode = 200,
                            Message = "Role updated successfully"
                        };
                    }
                }
                return new GeneralServiceResponseDto()
                {
                    IsSucceed = false,
                    StatusCode = 403,
                    Message = "You are not to change role of this user"
                };

            }

            return new GeneralServiceResponseDto()
            {
                IsSucceed = false,
                StatusCode = 403,
                Message = "You are not to change role of this user"
            };

        }







        public Task<UserInfoResult> GetUserDetailsByUserName(string userName)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<string>> GetUsernameListAsync()
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<UserInfoResult>> GetUsersListAsync()
        {
            throw new NotImplementedException();
        }

        public Task<LoginServiceResponseDto> MeAsync(MeDto meDto)
        {
            throw new NotImplementedException();
        }

        









        //GenerateJWTTokenAsync
        private async Task<string> GenerateJWTTokenAsync(ApplicationUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier,user.Id),
                new Claim("FirstName",user.FirstName),
                new Claim("LastName",user.LastName)
            };

            foreach(var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            //Created Our Own Secret
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            //Create Credential
            var signingCredentials = new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256);

            //Create new Token
            var tokenObject = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: signingCredentials
                );


            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;

        }

        //GenerateUserInfoObject
        private UserInfoResult GenerateUserInfoObject(ApplicationUser user, IEnumerable<string> Roles)
        {
            return new UserInfoResult()
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                UserName = user.UserName,
                Email = user.Email,
                CreatedAt = user.CreatedAt,
                Roles = user.Roles
            };
        }
    }
}
