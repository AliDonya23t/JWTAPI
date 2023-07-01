using JWTAPI.DTO.Requests;
using JWTAPI.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly DBJWTAPIContext _context;
        private IConfiguration _config;
        public LoginController(DBJWTAPIContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
        }
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(UserLoginRequest userLogin)
        {
            User? user = Authenticate(userLogin);

            if (user == null)
            {
                return NotFound("User not Found!!");
            }

            string token = Generate(user);
            return Ok(token);
        }

        private string Generate(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Username),
                new Claim(ClaimTypes.Role, user.IsAdmin?"Admin":"User"),
                new Claim(ClaimTypes.UserData, user.Bio)
            };
            var token = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private User? Authenticate(UserLoginRequest userLogin)
        {
            var currentUser = _context.Users.FirstOrDefault(u => u.Username.ToLower() == userLogin.Username.ToLower()
            && u.Password == userLogin.Password);
            if (currentUser == null)
            {
                return null;
            }
            return currentUser;
        }
    }
}
