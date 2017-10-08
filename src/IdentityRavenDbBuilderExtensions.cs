using Microsoft.Extensions.DependencyInjection;
using Raven.Client.Documents;
using SPR.AspNetCore.Identity.RavenDb;

namespace Microsoft.AspNetCore.Identity
{
    /// <summary>
    /// Contains extension methods to <see cref="IdentityBuilder"/> for adding Raven DB stores.
    /// </summary>
    public static class IdentityRavenDbBuilderExtensions
    {
        /// <summary>
        /// Adds a RavenDB implementation of identity information stores.
        /// </summary>
        /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
        public static IdentityBuilder AddRavenDbStores<TDocumentStore>(this IdentityBuilder builder)
                where TDocumentStore : class, IDocumentStore
                => builder
                    .AddRavenDbUserStore<TDocumentStore>()
                    .AddRavenDbRoleStore<TDocumentStore>();

        private static IdentityBuilder AddRavenDbUserStore<TDocumentStore>(
            this IdentityBuilder builder
        )
        {
            var userStoreType = typeof(RavenDbUserStore<,>).MakeGenericType(builder.UserType, typeof(TDocumentStore));

            builder.Services.AddScoped(
                typeof(IUserStore<>).MakeGenericType(builder.UserType),
                userStoreType
            );

            return builder;
        }

        private static IdentityBuilder AddRavenDbRoleStore<TDocumentStore>(
            this IdentityBuilder builder
        )
        {
            var roleStoreType = typeof(RavenDbRoleStore<,>).MakeGenericType(builder.RoleType, typeof(TDocumentStore));

            builder.Services.AddScoped(
                typeof(IRoleStore<>).MakeGenericType(builder.RoleType),
                roleStoreType
            );

            return builder;
        }

    }
}
