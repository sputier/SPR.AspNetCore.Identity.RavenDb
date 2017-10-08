using Microsoft.Extensions.DependencyInjection;
using Raven.Client.Documents;
using SPR.AspNetCore.Identity.RavenDb;
using System;
using System.Collections.Generic;
using System.Text;

namespace AspNetCore.Identity.RavenDB
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddRavenDocumentStore<TDocumentStore>(this IServiceCollection services, Func<TDocumentStore> documentStoreFactory)
            where TDocumentStore : class, IDocumentStore
        {
            return services.AddSingleton<RavenDbDatabaseCreator>()
                           .AddScoped<TDocumentStore>(serviceCollection =>
                           {
                               var store = (TDocumentStore)documentStoreFactory().Initialize();
                               serviceCollection.GetService<RavenDbDatabaseCreator>().EnsureCreated(store);
                               return store;
                           });
        }
    }
}
