using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Autenticacion.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {

        private readonly ILogger<AuthController> _logger;

        public AuthController(ILogger<AuthController> logger)
        {
            _logger = logger;
        }

        [HttpPost]
        [Route("token")]
        public async Task<IActionResult> Token(Credentials credentials)
        {
            if (!IsAdmin(credentials) && !IsUser(credentials))
            {
                return Unauthorized();
            }

            var secretKey = "this is my custom Secret key for authentication";
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey));

            var jwt = new JwtSecurityToken(
                claims: BuildClaims(credentials),
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
                );
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return Ok(token);
        }

        private bool IsUser(Credentials credentials)
        {
            return credentials.Username == "user" && credentials.Password == "user";
        }

        private bool IsAdmin(Credentials credentials)
        {
            return credentials.Username == "admin" && credentials.Password == "admin";
        }

        private Claim[] BuildClaims(Credentials credentials)
        {
            return new[]
            {
                new Claim("userType",IsAdmin(credentials)? "admin":"user")
            };
        }
    }

    public class Credentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
