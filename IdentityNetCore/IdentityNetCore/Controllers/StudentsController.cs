using IdentityNetCore.Models;
using Microsoft.AspNetCore.Mvc;

namespace IdentityNetCore.Controllers
{
    [AutoValidateAntiforgeryToken]
    // .Net adds antiforgery token automatically where needed
    public class StudentsController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // use this annotation where the form will change the "state" of the app
        public IActionResult SignUp(StudentViewModel model) 
        {
            return View("Result", model);
        }
    }
}
