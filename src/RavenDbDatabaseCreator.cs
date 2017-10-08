using Raven.Client.Documents;
using Raven.Client.ServerWide.Operations;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace SPR.AspNetCore.Identity.RavenDb
{
    internal class RavenDbDatabaseCreator
    {
        public void EnsureCreated(IDocumentStore documentStore)
        {
            var getDbOp = new GetDatabaseRecordOperation(documentStore.Database);
            var record = documentStore.Admin.Server.Send(getDbOp);
            if (record == null)
            {
                var createDatabaseOperation = new CreateDatabaseOperation(new Raven.Client.ServerWide.DatabaseRecord(documentStore.Database));
                documentStore.Admin.Server.Send(createDatabaseOperation);
            }
        }
    }
}
