using IdentityNetCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace IdentityNetCore.Data
{
    public class ApplicationContext : DbContext
    {
        public ApplicationContext(DbContextOptions options) : base(options)
        {
            
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Post>()
                .Property(p => p.CreatedAt)
                .HasDefaultValueSql("datetime('now')"); 
        }

        public DbSet<Post> Posts { get; set; }
    }
}
