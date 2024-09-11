﻿#region Copyright and License
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

using System.Net;
using System.Runtime.CompilerServices;

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

			foreach (var recordList in ResolveInternal<T>(name, recordType, recordClass, new ResolveLoopProtector()))
				foreach (var record in recordList)
					yield return record;
		}

		private IEnumerable<List<T>> ResolveInternal<T>(DomainName name, RecordType recordType, RecordClass recordClass, ResolveLoopProtector resolveLoopProtector) where T : DnsRecordBase
		{
			using (resolveLoopProtector.AddOrThrow(name, recordType, recordClass))
			{
				if (_cache.TryGetRecords(name, recordType, recordClass, out List<T>? records))
				{
					yield return records!;
				}

                _cache.Remove(name, recordType, recordClass);

                DnsMessage? msg = _dnsClient.Resolve(name, recordType, recordClass);

				if ((msg == null) || ((msg.ReturnCode != ReturnCode.NoError) && (msg.ReturnCode != ReturnCode.NxDomain)))
				{
					throw new Exception("DNS request failed");
				}

				CNameRecord? cName = msg.AnswerRecords.Where(x => (x.RecordType == RecordType.CName) && (x.RecordClass == recordClass) && x.Name.Equals(name)).OfType<CNameRecord>().FirstOrDefault();

				if (recordType != RecordType.CName && cName != null)
				{
					records = msg.AnswerRecords.Where(x => x.Name.Equals(cName.CanonicalName)).OfType<T>().ToList();
					if (records.Count > 0)
					{
						_cache.Add(name, recordType, recordClass, records, DnsSecValidationResult.Indeterminate, records.Min(x => x.TimeToLive));
						yield return records;
					}

					var recordLists = ResolveInternal<T>(cName.CanonicalName, recordType, recordClass, resolveLoopProtector);

					foreach (var recordList in recordLists)
					{
						if (recordList.Count > 0)
							_cache.Add(name, recordType, recordClass, recordList, DnsSecValidationResult.Indeterminate, recordList.Min(x => x.TimeToLive));

						yield return recordList;
					}
				}

				records = msg.AnswerRecords.Where(x => x.Name.Equals(name)).OfType<T>().ToList();

				if (records.Count > 0)
					_cache.Add(name, recordType, recordClass, records, DnsSecValidationResult.Indeterminate, records.Min(x => x.TimeToLive));

				yield return records;
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
		public async IAsyncEnumerable<T> ResolveAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, [EnumeratorCancellation] CancellationToken token = default(CancellationToken))
			where T : DnsRecordBase
		{
			_ = name ?? throw new ArgumentNullException(nameof(name), "Name must be provided");

			await foreach (var recordList in ResolveAsyncInternal<T>(name, recordType, recordClass, token, new ResolveLoopProtector()))
				foreach (var record in recordList)
					yield return record;
		}

		private async IAsyncEnumerable<List<T>> ResolveAsyncInternal<T>(DomainName name, RecordType recordType, RecordClass recordClass, [EnumeratorCancellation] CancellationToken token, ResolveLoopProtector resolveLoopProtector) where T : DnsRecordBase
		{
			using (resolveLoopProtector.AddOrThrow(name, recordType, recordClass))
			{
				if (_cache.TryGetRecords(name, recordType, recordClass, out List<T>? records))
				{
					yield return records!;
				}

                _cache.Remove(name, recordType, recordClass);

                var msg = await _dnsClient.ResolveAsync(name, recordType, recordClass, DnsQueryOptions.DefaultQueryOptions, token);

				if ((msg == null) || ((msg.ReturnCode != ReturnCode.NoError) && (msg.ReturnCode != ReturnCode.NxDomain)))
				{
					throw new Exception("DNS request failed");
				}

				var cName = msg.AnswerRecords.Where(x => (x.RecordType == RecordType.CName) && (x.RecordClass == recordClass) && x.Name.Equals(name)).OfType<CNameRecord>().FirstOrDefault();

				if (cName != null)
				{
					records = msg.AnswerRecords.Where(x => (x.RecordType == recordType) && (x.RecordClass == recordClass) && x.Name.Equals(cName.CanonicalName)).OfType<T>().ToList();
					if (records.Count > 0)
					{
						_cache.Add(name, recordType, recordClass, records, DnsSecValidationResult.Indeterminate, Math.Min(cName.TimeToLive, records.Min(x => x.TimeToLive)));
                        yield return records;
					}

					var recordLists = ResolveAsyncInternal<T>(cName.CanonicalName, recordType, recordClass, token, resolveLoopProtector);

					await foreach (var recordList in recordLists)
					{
						if (recordList.Count > 0)
							_cache.Add(name, recordType, recordClass, recordList, DnsSecValidationResult.Indeterminate, Math.Min(cName.TimeToLive, recordList.Min(x => x.TimeToLive)));

						yield return recordList;
					}
				}

				records = msg.AnswerRecords.Where(x => x.Name.Equals(name)).OfType<T>().ToList();

				if (records.Count > 0)
					_cache.Add(name, recordType, recordClass, records, DnsSecValidationResult.Indeterminate, records.Min(x => x.TimeToLive));

                yield return records;
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