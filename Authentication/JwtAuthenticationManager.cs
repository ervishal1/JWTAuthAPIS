using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthAPIS.Authentication
{
    public class JwtAuthenticationManager
    {
        public JwtAuthResponse Authenticate(string userName, string password)
        {
            //Validating UserName and Password
            if(userName != "user01" && password != "password123")
            {
                return null;
            }

            var JwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(Constants.JWT_SECURITY_KEY);
            var tokenExpiryTimeStamp = DateTime.Now.AddMinutes(Constants.JWT_TOKEN_VALIDITY_MINS);


			var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new List<Claim> 
                { 
                    new Claim("username", userName),
                    new Claim("userid","111-222-333"),
                    new Claim(ClaimTypes.PrimaryGroupSid,"User Group 01")
                }),
                Expires= tokenExpiryTimeStamp,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var securityToken = JwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = JwtSecurityTokenHandler.WriteToken(securityToken);

            return new JwtAuthResponse
            {
                token = token,
                user_name= userName,
                expires_in = (int) tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds
            };
        }
    }
}
