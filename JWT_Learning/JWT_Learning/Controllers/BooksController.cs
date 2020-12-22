using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JWT_Learning.JWTAuthentication;
using JWT_Learning.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWT_Learning.Controllers
{
    [Authorize(Roles = UserRoles.Admin)]
    [Route("api/[controller]")]
    [ApiController]
    public class BooksController : ControllerBase
    {
        private readonly List<Book> books;

        public BooksController()
        {
            books = new List<Book>()
                {
                    new Book() {Id = 1, Name = "AAA"},
                    new Book() {Id = 2, Name = "BBB"}
                };
        }


        [HttpGet]
        public IActionResult GetAll()
        {
            return Ok(books);
        }

        [AllowAnonymous]
        [HttpGet("{id}")]
        public IActionResult GetbyId(int id)
        {
            return Ok(books.Where(a => a.Id == id));
        }
    }
}