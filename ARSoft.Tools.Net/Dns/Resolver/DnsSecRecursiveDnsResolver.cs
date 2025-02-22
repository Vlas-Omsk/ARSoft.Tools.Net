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

namespace ARSoft.Tools.Net.Dns;

/* #FIXME

/// <summary>
///   <para>Recursive resolver</para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
///   </para>
/// </summary>
public class DnsSecRecursiveDnsResolver : IDnsSecResolver, IInternalDnsSecResolver<DnsSecRecursiveDnsResolver.ResolveContext>
{
	private class ResolveContext
	{
		public int QueryCount;
		public readonly ResolveLoopProtector LoopProtector = new();
	}

	private DnsCache _cache = new();
	private readonly DnsSecValidator<ResolveContext> _validator;
	private NameserverCache _nameserverCache = new();
	private readonly IClientTransport[] _transports = { new TcpClientTransport(), new UdpClientTransport() };

	private readonly IResolverHintStore _resolverHintStore;

	/// <summary>
	///   Provides a new instance with custom root server hints
	/// </summary>
	/// <param name="resolverHintStore"> The resolver hint store with the IP addresses of the root server and root DnsKey hints</param>
	public DnsSecRecursiveDnsResolver(IResolverHintStore? resolverHintStore = null)
	{
		_resolverHintStore = resolverHintStore ?? new StaticResolverHintStore();
		_validator = new DnsSecValidator<ResolveContext>(this, _resolverHintStore);
		IsResponseValidationEnabled = true;
		QueryTimeout = 2000;
		MaximumReferralCount = 20;
	}

	/// <summary>
	///   Gets or sets a value indicating how much referrals for a single query could be performed
	/// </summary>
	public int MaximumReferralCount { get; set; }

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
	public async IAsyncEnumerable<T> ResolveAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, [EnumeratorCancellation] CancellationToken token = default)
		where T : DnsRecordBase
	{
		var res = await ResolveSecureAsync<T>(name, recordType, recordClass, token);

		foreach (var record in res.Records)
			yield return record;
	}

	/// <summary>
	///   Resolves specified records.
	/// </summary>
	/// <typeparam name="T"> Type of records, that should be returned </typeparam>
	/// <param name="name"> Domain, that should be queried </param>
	/// <param name="recordType"> Type the should be queried </param>
	/// <param name="recordClass"> Class the should be queried </param>
	/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
	public DnsSecResult<T> ResolveSecure<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
		where T : DnsRecordBase
	{
		return ResolveSecureAsync<T>(name, recordType, recordClass).GetAwaiter().GetResult();
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
	public Task<DnsSecResult<T>> ResolveSecureAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, CancellationToken token = default)
		where T : DnsRecordBase
	{
		_ = name ?? throw new ArgumentNullException(nameof(name), "Name must be provided");

		return ResolveAsyncInternal<T>(name, recordType, recordClass, new ResolveContext(), token);
	}

	private async Task<DnsMessage?> ResolveMessageAsync(DomainName name, RecordType recordType, RecordClass recordClass, ResolveContext resolveContext, CancellationToken token)
	{
		for (; resolveContext.QueryCount <= MaximumReferralCount; resolveContext.QueryCount++)
		{
			DnsMessage? msg = await new DnsClient(GetBestNameservers(recordType == RecordType.Ds ? name.GetParentName() : name), _transports, true, QueryTimeout)
			{
				IsResponseValidationEnabled = IsResponseValidationEnabled,
				Is0x20ValidationEnabled = Is0x20ValidationEnabled
			}.ResolveAsync(name, recordType, recordClass, new DnsQueryOptions()
			{
				IsRecursionDesired = false,
				IsCheckingDisabled = true,
				EDnsOptions = DnsQueryOptions.DefaultDnsSecQueryOptions.EDnsOptions
			}, token);

			if ((msg != null) && ((msg.ReturnCode == ReturnCode.NoError) || (msg.ReturnCode == ReturnCode.NxDomain)))
			{
				if (msg.IsAuthoritiveAnswer)
					return msg;

				List<NsRecord> referralRecords = msg.AuthorityRecords
					.Where(x =>
						(x.RecordType == RecordType.Ns)
						&& (name.Equals(x.Name) || name.IsSubDomainOf(x.Name)))
					.OfType<NsRecord>()
					.ToList();

				if (referralRecords.Count > 0)
				{
					if (referralRecords.GroupBy(x => x.Name).Count() == 1)
					{
						var newServers = referralRecords.Join(msg.AdditionalRecords.OfType<AddressRecordBase>(), x => x.NameServer, x => x.Name, (x, y) => new { y.Address, TimeToLive = Math.Min(x.TimeToLive, y.TimeToLive) }).ToList();

						if (newServers.Count > 0)
						{
							var zone = referralRecords.First().Name;

							foreach (var newServer in newServers)
							{
								_nameserverCache.Add(zone, newServer.Address, newServer.TimeToLive);
							}

							continue;
						}
						else
						{
							NsRecord firstReferal = referralRecords.First();

							var newLookedUpServers = await ResolveHostWithTtlAsync(firstReferal.NameServer, resolveContext, token);

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

	private async Task<DnsSecResult<T>> ResolveAsyncInternal<T>(DomainName name, RecordType recordType, RecordClass recordClass, ResolveContext resolveContext, CancellationToken token)
		where T : DnsRecordBase
	{
		using (resolveContext.LoopProtector.AddOrThrow(name, recordType, recordClass))
		{
			if (_cache.TryGetRecords(name, recordType, recordClass, out CacheRecordList<T>? cachedResults))
			{
				return new DnsSecResult<T>(cachedResults!, cachedResults!.ValidationResult);
			}

			if (_cache.TryGetRecords(name, RecordType.CName, recordClass, out CacheRecordList<CNameRecord>? cachedCNames))
			{
				var canonicalName = cachedCNames!.First().CanonicalName;
				var cNameResult = await ResolveAsyncInternal<T>(canonicalName, recordType, recordClass, resolveContext, token);
				return new DnsSecResult<T>(cNameResult.Records, cachedCNames!.ValidationResult == cNameResult.ValidationResult ? cachedCNames.ValidationResult : DnsSecValidationResult.Unsigned);
			}

			var msg = await ResolveMessageAsync(name, recordType, recordClass, resolveContext, token);

			// check for cname
			var cNameRecords = msg?.AnswerRecords.Where(x => (x.RecordType == RecordType.CName) && (x.RecordClass == recordClass) && x.Name.Equals(name)).ToList();
			if (cNameRecords?.Count > 0)
			{
				var cNameValidationResult = await _validator.ValidateAsync(name, RecordType.CName, recordClass, msg!, cNameRecords, resolveContext, token);
				if ((cNameValidationResult == DnsSecValidationResult.Bogus) || (cNameValidationResult == DnsSecValidationResult.Indeterminate))
					throw new DnsSecValidationException("CNAME record could not be validated");

				_cache.Add(name, RecordType.CName, recordClass, cNameRecords, cNameValidationResult, cNameRecords.Min(x => x.TimeToLive));

				var canonicalName = ((CNameRecord) cNameRecords.First()).CanonicalName;

				var matchingAdditionalRecords = msg?.AnswerRecords.Where(x => (x.RecordType == recordType) && (x.RecordClass == recordClass) && x.Name.Equals(canonicalName)).ToList();
				if (matchingAdditionalRecords?.Count > 0)
				{
					var matchingValidationResult = await _validator.ValidateAsync(canonicalName, recordType, recordClass, msg!, matchingAdditionalRecords, resolveContext, token);
					if ((matchingValidationResult == DnsSecValidationResult.Bogus) || (matchingValidationResult == DnsSecValidationResult.Indeterminate))
						throw new DnsSecValidationException("CNAME matching records could not be validated");

					var validationResult = cNameValidationResult == matchingValidationResult ? cNameValidationResult : DnsSecValidationResult.Unsigned;
					_cache.Add(canonicalName, recordType, recordClass, matchingAdditionalRecords, validationResult, matchingAdditionalRecords.Min(x => x.TimeToLive));

					return new DnsSecResult<T>(matchingAdditionalRecords.OfType<T>().ToList(), validationResult);
				}

				var cNameResults = await ResolveAsyncInternal<T>(canonicalName, recordType, recordClass, resolveContext, token);
				return new DnsSecResult<T>(cNameResults.Records, cNameValidationResult == cNameResults.ValidationResult ? cNameValidationResult : DnsSecValidationResult.Unsigned);
			}

			// check for "normal" answer
			var answerRecords = msg?.AnswerRecords.Where(x => (x.RecordType == recordType) && (x.RecordClass == recordClass) && x.Name.Equals(name)).ToList();
			if (answerRecords?.Count > 0)
			{
				var validationResult = await _validator.ValidateAsync(name, recordType, recordClass, msg!, answerRecords, resolveContext, token);
				if ((validationResult == DnsSecValidationResult.Bogus) || (validationResult == DnsSecValidationResult.Indeterminate))
					throw new DnsSecValidationException("Response records could not be validated");

				_cache.Add(name, recordType, recordClass, answerRecords, validationResult, answerRecords.Min(x => x.TimeToLive));
				return new DnsSecResult<T>(answerRecords.OfType<T>().ToList(), validationResult);
			}

			// check for negative answer
			var soaRecord = msg?.AuthorityRecords
				.Where(x =>
					(x.RecordType == RecordType.Soa)
					&& (name.Equals(x.Name) || name.IsSubDomainOf(x.Name)))
				.OfType<SoaRecord>()
				.FirstOrDefault();

			if (soaRecord != null)
			{
				var validationResult = await _validator.ValidateAsync(name, recordType, recordClass, msg!, answerRecords ?? new List<DnsRecordBase>(), resolveContext, token);
				if ((validationResult == DnsSecValidationResult.Bogus) || (validationResult == DnsSecValidationResult.Indeterminate))
					throw new DnsSecValidationException("Negative answer could not be validated");

				_cache.Add(name, recordType, recordClass, new List<DnsRecordBase>(), validationResult, soaRecord.NegativeCachingTTL);
				return new DnsSecResult<T>(new List<T>(), validationResult);
			}

			// authoritive response does not contain answer
			throw new Exception("Could not resolve " + name.ToString(false));
		}
	}


	private async Task<List<Tuple<IPAddress, int>>> ResolveHostWithTtlAsync(DomainName name, ResolveContext resolveContext, CancellationToken token)
	{
		var result = new List<Tuple<IPAddress, int>>();

		var aaaaRecords = await ResolveAsyncInternal<AaaaRecord>(name, RecordType.Aaaa, RecordClass.INet, resolveContext, token);
		result.AddRange(aaaaRecords.Records.Select(x => new Tuple<IPAddress, int>(x.Address, x.TimeToLive)));

		var aRecords = await ResolveAsyncInternal<ARecord>(name, RecordType.A, RecordClass.INet, resolveContext, token);
		result.AddRange(aRecords.Records.Select(x => new Tuple<IPAddress, int>(x.Address, x.TimeToLive)));

		return result;
	}

	private IEnumerable<IPAddress> GetBestNameservers(DomainName name)
	{
		var rnd = new Random();

		while (name.LabelCount > 0)
		{
			if (_nameserverCache.TryGetAddresses(name, out var cachedAddresses))
			{
				return cachedAddresses!.OrderBy(x => x.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1).ThenBy(_ => rnd.Next());
			}

			name = name.GetParentName();
		}

		return _resolverHintStore.RootServers.OrderBy(x => x.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1).ThenBy(_ => rnd.Next());
	}

	Task<DnsMessage?> IInternalDnsSecResolver<ResolveContext>.ResolveMessageAsync(DomainName name, RecordType recordType, RecordClass recordClass, ResolveContext resolveContext, CancellationToken token)
	{
		return ResolveMessageAsync(name, recordType, recordClass, resolveContext, token);
	}

	Task<DnsSecResult<TRecord>> IInternalDnsSecResolver<ResolveContext>.ResolveSecureAsync<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, ResolveContext resolveContext, CancellationToken token)
	{
		return ResolveAsyncInternal<TRecord>(name, recordType, recordClass, resolveContext, token);
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

	~DnsSecRecursiveDnsResolver()
	{
		Dispose(false);
	}
}
*/