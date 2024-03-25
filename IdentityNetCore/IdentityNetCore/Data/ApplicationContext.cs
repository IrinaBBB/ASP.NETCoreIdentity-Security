using IdentityNetCore.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityNetCore.Data
{
    public class ApplicationContext : IdentityDbContext
    {
        public ApplicationContext()
        {
            
        }
        public ApplicationContext(DbContextOptions options) : base(options)
        {
            
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // This Function Call Should be here 
            base.OnModelCreating(modelBuilder);
            // This Function Call Should be here 

            modelBuilder.Entity<Post>()
                .Property(p => p.CreatedAt)
                .HasDefaultValueSql("datetime('now')"); 
        }

        public DbSet<Post> Posts { get; set; }
    }
}
