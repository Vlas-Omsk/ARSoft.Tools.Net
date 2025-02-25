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
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace ARSoft.Tools.Net.Dns
{
	/* #FIXME
	
	/// <summary>
	///   <para>Recursive resolver</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
	///   </para>
	/// </summary>
	public class RecursiveDnsResolver : IDnsResolver
	{
		private class ResolveContext
		{
			public int QueryCount;
			public readonly ResolveLoopProtector LoopProtector = new();
		}

		private DnsCache _cache = new DnsCache();
		private NameserverCache _nameserverCache = new NameserverCache();
		private IClientTransport[] _transports = { new TcpClientTransport(), new UdpClientTransport() };

		private readonly IResolverHintStore _resolverHintStore;

		/// <summary>
		///   Provides a new instance with custom root server hints
		/// </summary>
		/// <param name="resolverHintStore"> The resolver hint store with the IP addresses of the root server hints</param>
		public RecursiveDnsResolver(IResolverHintStore? resolverHintStore = null)
		{
			_resolverHintStore = resolverHintStore ?? new StaticResolverHintStore();
			IsResponseValidationEnabled = true;
			QueryTimeout = 2000;
			MaximumReferalCount = 20;
		}

		/// <summary>
		///   Gets or sets a value indicating how much referals for a single query could be performed
		/// </summary>
		public int MaximumReferalCount { get; set; }

		/// <summary>
		///   Milliseconds after which a query times out.
		/// </summary>
		public int QueryTimeout { get; set; }

		/// <summary>
		///   Gets or set a value indicating whether the response is validated as described in
		///   <a href="http://tools.ietf.org/id/draft-vixie-dnsext-dns0x20-00.txt">draft-vixie-dnsext-dns0x20-00</a>
		/// </summary>
		public bool IsResponseValidationEnabled { get; set; }

		/// <summary>
		///   Gets or set a value indicating whether the query labels are used for additional validation as described in
		///   <a href="http://tools.ietf.org/id/draft-vixie-dnsext-dns0x20-00.txt">draft-vixie-dnsext-dns0x20-00</a>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public bool Is0x20ValidationEnabled { get; set; }

		/// <summary>
		///   Clears the record cache
		/// </summary>
		public void ClearCache()
		{
			_cache = new DnsCache();
			_nameserverCache = new NameserverCache();
		}

		/// <summary>
		///   Resolves specified records.
		/// </summary>
		/// <typeparam name="T"> Type of records, that should be returned </typeparam>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
		public IEnumerable<T> Resolve<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
			where T : DnsRecordBase
		{
			var enumerator = ResolveAsync<T>(name, recordType, recordClass).GetAsyncEnumerator();

			while (enumerator.MoveNextAsync().GetAwaiter().GetResult())
				yield return enumerator.Current;
		}

		/// <summary>
		///   Resolves specified records as an asynchronous operation.
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

			foreach (var item in await ResolveAsyncInternal<T>(name, recordType, recordClass, new ResolveContext(), token))
				yield return item;
		}

		private async Task<DnsMessage> ResolveMessageAsync(DomainName name, RecordType recordType, RecordClass recordClass, ResolveContext state, CancellationToken token)
		{
			for (; state.QueryCount <= MaximumReferalCount; state.QueryCount++)
			{
				DnsMessage? msg = await new DnsClient(GetBestNameservers(recordType == RecordType.Ds ? name.GetParentName() : name), _transports, false, QueryTimeout)
				{
					IsResponseValidationEnabled = IsResponseValidationEnabled,
					Is0x20ValidationEnabled = Is0x20ValidationEnabled
				}.ResolveAsync(name, recordType, recordClass, new DnsQueryOptions()
				{
					IsRecursionDesired = false,
					EDnsOptions = DnsQueryOptions.DefaultQueryOptions.EDnsOptions
				}, token);

				if ((msg != null) && ((msg.ReturnCode == ReturnCode.NoError) || (msg.ReturnCode == ReturnCode.NxDomain)))
				{
					if (msg.IsAuthoritiveAnswer)
						return msg;

					List<NsRecord> referalRecords = msg.AuthorityRecords
						.Where(x =>
							(x.RecordType == RecordType.Ns)
							&& (name.Equals(x.Name) || name.IsSubDomainOf(x.Name)))
						.OfType<NsRecord>()
						.ToList();

					if (referalRecords.Count > 0)
					{
						if (referalRecords.GroupBy(x => x.Name).Count() == 1)
						{
							var newServers = referalRecords.Join(msg.AdditionalRecords.OfType<AddressRecordBase>(), x => x.NameServer, x => x.Name, (x, y) => new { y.Address, TimeToLive = Math.Min(x.TimeToLive, y.TimeToLive) }).ToList();

							if (newServers.Count > 0)
							{
								DomainName zone = referalRecords.First().Name;

								foreach (var newServer in newServers)
								{
									_nameserverCache.Add(zone, newServer.Address, newServer.TimeToLive);
								}

								continue;
							}
							else
							{
								NsRecord firstReferal = referalRecords.First();

								var newLookedUpServers = await ResolveHostWithTtlAsync(firstReferal.NameServer, state, token);

								foreach (var newServer in newLookedUpServers)
								{
									_nameserverCache.Add(firstReferal.Name, newServer.Item1, Math.Min(firstReferal.TimeToLive, newServer.Item2));
								}

								if (newLookedUpServers.Count > 0)
									continue;
							}
						}
					}

					// Response of best known server is not authoritive and has no referrals --> No chance to get a result
					throw new Exception("Could not resolve " + name.ToString(false));
				}
			}

			// query limit reached without authoritive answer
			throw new Exception("Could not resolve " + name.ToString(false));
		}

		private async Task<List<T>> ResolveAsyncInternal<T>(DomainName name, RecordType recordType, RecordClass recordClass, ResolveContext context, CancellationToken token)
			where T : DnsRecordBase
		{
			using (context.LoopProtector.AddOrThrow(name, recordType, recordClass))
			{
				if (_cache.TryGetRecords(name, recordType, recordClass, out List<T>? cachedResults))
				{
					return cachedResults!;
				}

				if (_cache.TryGetRecords(name, RecordType.CName, recordClass, out List<CNameRecord>? cachedCNames))
				{
					var canonicalName = cachedCNames!.First().CanonicalName;
					return await ResolveAsyncInternal<T>(canonicalName, recordType, recordClass, context, token);
				}

				DnsMessage msg = await ResolveMessageAsync(name, recordType, recordClass, context, token);

				// check for cname
				List<DnsRecordBase> cNameRecords = msg.AnswerRecords.Where(x => (x.RecordType == RecordType.CName) && (x.RecordClass == recordClass) && x.Name.Equals(name)).ToList();
				if (cNameRecords.Count > 0)
				{
					_cache.Add(name, RecordType.CName, recordClass, cNameRecords, DnsSecValidationResult.Indeterminate, cNameRecords.Min(x => x.TimeToLive));

					DomainName canonicalName = ((CNameRecord) cNameRecords.First()).CanonicalName;

					List<DnsRecordBase> matchingAdditionalRecords = msg.AnswerRecords.Where(x => (x.RecordType == recordType) && (x.RecordClass == recordClass) && x.Name.Equals(canonicalName)).ToList();
					if (matchingAdditionalRecords.Count > 0)
					{
						_cache.Add(canonicalName, recordType, recordClass, matchingAdditionalRecords, DnsSecValidationResult.Indeterminate, matchingAdditionalRecords.Min(x => x.TimeToLive));
						return matchingAdditionalRecords.OfType<T>().ToList();
					}

					return await ResolveAsyncInternal<T>(canonicalName, recordType, recordClass, context, token);
				}

				// check for "normal" answer
				List<DnsRecordBase> answerRecords = msg.AnswerRecords.Where(x => (x.RecordType == recordType) && (x.RecordClass == recordClass) && x.Name.Equals(name)).ToList();
				if (answerRecords.Count > 0)
				{
					_cache.Add(name, recordType, recordClass, answerRecords, DnsSecValidationResult.Indeterminate, answerRecords.Min(x => x.TimeToLive));
					return answerRecords.OfType<T>().ToList();
				}

				// check for negative answer
				SoaRecord? soaRecord = msg.AuthorityRecords
					.Where(x =>
						(x.RecordType == RecordType.Soa)
						&& (name.Equals(x.Name) || name.IsSubDomainOf(x.Name)))
					.OfType<SoaRecord>()
					.FirstOrDefault();

				if (soaRecord != null)
				{
					_cache.Add(name, recordType, recordClass, new List<DnsRecordBase>(), DnsSecValidationResult.Indeterminate, soaRecord.NegativeCachingTTL);
					return new List<T>();
				}

				// authoritive response does not contain answer
				throw new Exception("Could not resolve " + name.ToString(false));
			}
		}

		private async Task<List<Tuple<IPAddress, int>>> ResolveHostWithTtlAsync(DomainName name, ResolveContext state, CancellationToken token)
		{
			List<Tuple<IPAddress, int>> result = new List<Tuple<IPAddress, int>>();

			var aaaaRecords = await ResolveAsyncInternal<AaaaRecord>(name, RecordType.Aaaa, RecordClass.INet, state, token);
			result.AddRange(aaaaRecords.Select(x => new Tuple<IPAddress, int>(x.Address, x.TimeToLive)));

			var aRecords = await ResolveAsyncInternal<ARecord>(name, RecordType.A, RecordClass.INet, state, token);
			result.AddRange(aRecords.Select(x => new Tuple<IPAddress, int>(x.Address, x.TimeToLive)));

			return result;
		}

		private IEnumerable<IPAddress> GetBestNameservers(DomainName name)
		{
			var rnd = new Random();

			while (name.LabelCount > 0)
			{
				if (_nameserverCache.TryGetAddresses(name, out var cachedAddresses))
				{
					return cachedAddresses!.OrderBy(x => x.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1).ThenBy(x => rnd.Next());
				}

				name = name.GetParentName();
			}

			return _resolverHintStore.RootServers.OrderBy(x => x.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1).ThenBy(x => rnd.Next());
		}

		void IDisposable.Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool isDisposing)
		{
			foreach (var transport in _transports)
			{
				transport.Dispose();
			}
		}

		~RecursiveDnsResolver()
		{
			Dispose(false);
		}
	}
	*/
}