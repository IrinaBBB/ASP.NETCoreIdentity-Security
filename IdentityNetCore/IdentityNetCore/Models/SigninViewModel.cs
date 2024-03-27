using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models
{
    public class SigninViewModel
    {
        [Required]
        [DataType(DataType.EmailAddress, ErrorMessage = "Email is missing or invalid")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password, ErrorMessage = "Incorrect or missing password")]
        public string Password { get; set; }

        public bool RemeberMe { get; set; }
    }
}


