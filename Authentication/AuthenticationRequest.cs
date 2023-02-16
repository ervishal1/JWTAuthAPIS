using System;

namespace JWTAuthAPIS.Authentication
{
	[Serializable]
	public class AuthenticationRequest
	{
		public string UserName { get; set; }
		public string Password { get; set; }
	}
}
