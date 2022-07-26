using System.ComponentModel.DataAnnotations;

namespace TicketSupport.API.Models
{
	public class ResetPasswordViewModel
	{
		[Required(ErrorMessage = "Username is required")]
		public string username { get; set; }
		[Required(ErrorMessage = "New Password is required")]
		public string newPassword { get; set; }
		[Required(ErrorMessage = "Confirm Password is required")]
		public string confirmPassword { get; set; }

		public string token { get; set; }
	}
}
