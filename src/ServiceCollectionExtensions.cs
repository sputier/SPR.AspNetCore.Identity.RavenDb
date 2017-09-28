using Microsoft.Extensions.DependencyInjection;
using Raven.Client.Documents;
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
            return services.AddScoped<TDocumentStore>((serviceCollection) => (TDocumentStore)documentStoreFactory().Initialize());
        }
    }
}
