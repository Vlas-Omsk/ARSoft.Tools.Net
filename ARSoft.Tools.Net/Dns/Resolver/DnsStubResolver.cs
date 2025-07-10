#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion

using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Stub resolver</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
	///   </para>
	/// </summary>
	public class DnsStubResolver : IDnsResolver
	{
		private readonly DnsClient _dnsClient;
		private DnsCache _cache = new DnsCache();

		/// <summary>
		///   Provides a new instance using the local configured DNS servers
		/// </summary>
		public DnsStubResolver()
			: this(DnsClient.Default) { }

		/// <summary>
		///   Provides a new instance using a custom <see cref="DnsClient">DNS client</see>
		/// </summary>
		/// <param name="dnsClient"> The <see cref="DnsClient">DNS client</see> to use </param>
		public DnsStubResolver(DnsClient dnsClient)
		{
			_dnsClient = dnsClient;
		}

		/// <summary>
		///   Provides a new instance using a list of custom DNS servers and a custom query timeout
		/// </summary>
		/// <param name="servers"> The list of servers to use </param>
		/// <param name="queryTimeout"> The query timeout in milliseconds </param>
		public DnsStubResolver(IEnumerable<IPAddress> servers, int queryTimeout = 10000)
			: this(new DnsClient(servers, queryTimeout)) { }

		/// <summary>
		///   Provides a new instance using a list of custom DNS servers and a custom query timeout
		/// </summary>
		/// <param name="dnsOverHttpsEndpoint"> The uri of a DNS over HTTPS server to use </param>
		/// <param name="queryTimeout"> The query timeout in milliseconds </param>
		public DnsStubResolver(Uri dnsOverHttpsEndpoint, int queryTimeout = 10000)
			: this(new DnsClient(new[] { IPAddress.Any, }, new IClientTransport[] { new HttpsClientTransport(dnsOverHttpsEndpoint) }, true, queryTimeout)) { }

		/// <summary>
		///   Queries a the upstream DNS server(s) for specified records.
		/// </summary>
		/// <typeparam name="T"> Type of records, that should be returned </typeparam>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
		public IEnumerable<T> Resolve<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
			where T : DnsRecordBase
		{
			_ = name ?? throw new ArgumentNullException(nameof(name), "Name must be provided");

            var cacheItem = _cache.GetAndLock(new DnsCache.CacheKey(name, recordType, recordClass));

            if (cacheItem.State == PoolCacheItemState.Success)
            {
                cacheItem.Release();

                return cacheItem.Value!.Records.List.OfType<T>();
            }
            else if (cacheItem.State == PoolCacheItemState.Failed)
            {
				cacheItem.Reset();

                // Continue processing
            }
            else if (cacheItem.State == PoolCacheItemState.Pending)
            {
                // Continue processing
            }
            else
            {
                throw new NotSupportedException("State not supported");
            }

            try
            {
                var records = ResolveInternal<T>(name, recordType, recordClass, new ResolveLoopProtector()).ToList();

                cacheItem.SetSuccessAnsRelease(
                    new DnsCache.CacheValue(
                        new DnsCache.CacheRecordList(records, DnsSecValidationResult.Indeterminate),
                        records.Count == 0 ? 0 : records.Min(x => x.TimeToLive)
                    )
                );

				return records;
            }
            catch (Exception ex)
            {
                cacheItem.SetFailedAndRelease(ex);

                throw;
            }
        }

		private IEnumerable<T> ResolveInternal<T>(DomainName name, RecordType recordType, RecordClass recordClass, ResolveLoopProtector resolveLoopProtector) where T : DnsRecordBase
		{
			using (resolveLoopProtector.AddOrThrow(name, recordType, recordClass))
			{
				DnsMessage? msg = _dnsClient.Resolve(name, recordType, recordClass);

				if ((msg == null) ||
					((msg.ReturnCode != ReturnCode.NoError) && (msg.ReturnCode != ReturnCode.NxDomain)))
				{
					throw new Exception("DNS request failed");
				}

				CNameRecord? cName = msg.AnswerRecords
					.Where(x => 
						(x.RecordType == RecordType.CName) &&
						(x.RecordClass == recordClass) &&
						x.Name.Equals(name)
					)
					.OfType<CNameRecord>()
					.FirstOrDefault();

				if (recordType != RecordType.CName && cName != null)
				{
					var answerCnameRecords = msg.AnswerRecords.Where(x => x.Name.Equals(cName.CanonicalName)).OfType<T>();

					foreach (var record in answerCnameRecords)
						yield return record;

					var nextRecords = ResolveInternal<T>(cName.CanonicalName, recordType, recordClass, resolveLoopProtector);

                    foreach (var record in nextRecords)
                        yield return record;
				}

                var answerRecords = msg.AnswerRecords.Where(x => x.Name.Equals(name)).OfType<T>();

                foreach (var record in answerRecords)
                    yield return record;
			}
		}

		/// <summary>
		///   Queries a the upstream DNS server(s) for specified records as an asynchronous operation.
		/// </summary>
		/// <typeparam name="T"> Type of records, that should be returned </typeparam>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
		public async Task<IEnumerable<T>> ResolveAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, CancellationToken token = default)
			where T : DnsRecordBase
		{
			_ = name ?? throw new ArgumentNullException(nameof(name), "Name must be provided");

            var cacheItem = await _cache.GetAndLockAsync(new DnsCache.CacheKey(name, recordType, recordClass), token);

            if (cacheItem.State == PoolCacheItemState.Success)
            {
                cacheItem.Release();

                return cacheItem.Value!.Records.List.OfType<T>();
            }
            else if (cacheItem.State == PoolCacheItemState.Failed)
            {
				await cacheItem.ResetAsync();

                // Retrying
            }
            else if (cacheItem.State == PoolCacheItemState.Pending)
            {
                // Resolving
            }
            else
            {
                throw new NotSupportedException("State not supported");
            }

			cacheItem.SetTask(async cancellationToken =>
			{
				try
				{
					var records = await ResolveAsyncInternal<T>(name, recordType, recordClass, cancellationToken, new ResolveLoopProtector()).ToListAsync(cancellationToken);

					cacheItem.SetSuccessAnsRelease(
						new DnsCache.CacheValue(
							new DnsCache.CacheRecordList(records, DnsSecValidationResult.Indeterminate),
							records.Count == 0 ? 0 : records.Min(x => x.TimeToLive)
						)
					);
				}
				catch (Exception ex)
				{
					cacheItem.SetFailedAndRelease(ex);

                    throw;
                }
			});

			await cacheItem.WaitAsync(token);

			return cacheItem.Value!.Records.List.OfType<T>();
		}

		private async IAsyncEnumerable<T> ResolveAsyncInternal<T>(DomainName name, RecordType recordType, RecordClass recordClass, [EnumeratorCancellation] CancellationToken token, ResolveLoopProtector resolveLoopProtector) where T : DnsRecordBase
		{
			using (resolveLoopProtector.AddOrThrow(name, recordType, recordClass))
			{
                var msg = await _dnsClient.ResolveAsync(name, recordType, recordClass, DnsQueryOptions.DefaultQueryOptions, token);

                if ((msg == null) ||
                    ((msg.ReturnCode != ReturnCode.NoError) && (msg.ReturnCode != ReturnCode.NxDomain)))
                {
                    throw new Exception("DNS request failed");
                }

                var cName = msg.AnswerRecords
                    .Where(x =>
                        (x.RecordType == RecordType.CName) &&
                        (x.RecordClass == recordClass) &&
                        x.Name.Equals(name)
                    )
                    .OfType<CNameRecord>()
                    .FirstOrDefault();

                var records = new List<T>();

                if (cName != null)
                {
                    var answerCnameRecords = msg.AnswerRecords.Where(x => x.Name.Equals(cName.CanonicalName)).OfType<T>();

					foreach (var record in answerCnameRecords)
						yield return record;

                    var nextRecords = ResolveAsyncInternal<T>(cName.CanonicalName, recordType, recordClass, token, resolveLoopProtector);

					await foreach (var record in nextRecords)
                        yield return record;
                }

                var answerRecords = msg.AnswerRecords.Where(x => x.Name.Equals(name)).OfType<T>();

                foreach (var record in answerRecords)
                    yield return record;
            }
		}

		/// <summary>
		///   Clears the record cache
		/// </summary>
		public void ClearCache()
		{
			_cache = new DnsCache();
		}

		void IDisposable.Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool isDisposing) { }

		~DnsStubResolver()
		{
			Dispose(false);
		}
	}
}