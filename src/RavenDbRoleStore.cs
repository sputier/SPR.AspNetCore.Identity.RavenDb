using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using System;
using Raven.Client.Documents.Session;
using Raven.Client.Documents;
using Raven.Client.Exceptions;
using System.Linq;

namespace SPR.AspNetCore.Identity.RavenDb
{
    public class RavenDbRoleStore<TDocumentStore> : RavenDbRoleStore<IdentityRole<string>, TDocumentStore>
        where TDocumentStore : class, IDocumentStore
    {
        public RavenDbRoleStore(TDocumentStore documentStore, IdentityErrorDescriber identityErrorDescriber = null)
            : base(documentStore, identityErrorDescriber)
        {
        }
    }
    
    public class RavenDbRoleStore<TRole, TDocumentStore> : IQueryableRoleStore<TRole>
        where TRole : IdentityRole<string>
        where TDocumentStore : class, IDocumentStore
    {
        private bool _disposed;

        private readonly TDocumentStore _documentStore;
        private readonly IdentityErrorDescriber _identityErrorDescriber;
        private readonly Lazy<IAsyncDocumentSession> _currentAsyncSession;
        private readonly Lazy<IDocumentSession> _currentSyncSession;

        private TDocumentStore DocumentStore
            => _documentStore;

        private IdentityErrorDescriber ErrorDescriber
            => _identityErrorDescriber;

        private IAsyncDocumentSession CurrentAsyncSession
            => _currentAsyncSession.Value;

        private IDocumentSession CurrentSyncSession
            => _currentSyncSession.Value;

        public IQueryable<TRole> Roles
            => CurrentSyncSession.Query<TRole>();

        public RavenDbRoleStore(TDocumentStore documentStore,
                                IdentityErrorDescriber identityErrorDescriber = null)
        {
            _documentStore = documentStore;
            _identityErrorDescriber = identityErrorDescriber;

            _currentAsyncSession = new Lazy<IAsyncDocumentSession>(() => _documentStore.OpenAsyncSession());
        }

        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            try
            {
                await CurrentAsyncSession.StoreAsync(role, cancellationToken);
                await CurrentAsyncSession.SaveChangesAsync(cancellationToken);
            }
            catch (ConcurrencyException ex)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            try
            {
                CurrentAsyncSession.Delete(role.Id);
                await CurrentAsyncSession.SaveChangesAsync(cancellationToken);
            }
            catch (ConcurrencyException ex)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }

            return IdentityResult.Success;
        }

        public async Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (roleId == null)
                throw new ArgumentNullException(nameof(roleId));

            return Roles.FirstOrDefault(role => role.Id == roleId);
        }

        public async Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (normalizedRoleName == null)
                throw new ArgumentNullException(nameof(normalizedRoleName));

            return Roles.FirstOrDefault(role => role.NormalizedName == normalizedRoleName);
        }

        public async Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return await Task.FromResult(role.NormalizedName);
        }

        public async Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return await Task.FromResult(role.Id);
        }

        public async Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return await Task.FromResult(role.Name);
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            if (normalizedName == null)
                throw new ArgumentNullException(nameof(normalizedName));

            role.NormalizedName = normalizedName ?? throw new ArgumentNullException(nameof(normalizedName));

            return Task.CompletedTask;
        }

        public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            if (roleName == null)
                throw new ArgumentNullException(nameof(roleName));

            role.Name = roleName ?? throw new ArgumentNullException(nameof(roleName));

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            var dbRole = await CurrentAsyncSession.LoadAsync<TRole>(role.Id, cancellationToken);

            try
            {
                CurrentAsyncSession.Advanced.Evict(dbRole);
                await CurrentAsyncSession.StoreAsync(role, dbRole.Id, cancellationToken);
                await CurrentAsyncSession.SaveChangesAsync(cancellationToken);
            }
            catch (ConcurrencyException ex)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }

            return IdentityResult.Success;
        }

        /// <summary>
        /// Throws if this class has been disposed.
        /// </summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        /// <summary>
        /// Dispose the store
        /// </summary>
        public void Dispose()
        {
            _disposed = true;
        }
    }
}
