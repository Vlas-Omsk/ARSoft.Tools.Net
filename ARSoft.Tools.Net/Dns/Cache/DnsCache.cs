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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace ARSoft.Tools.Net.Dns
{
	internal enum PoolCacheItemState
    {
        Pending,
        Success,
        Failed
    }

    internal class DnsCache
	{
        public class CacheRecordList
        {
            public IReadOnlyCollection<DnsRecordBase> List { get; }
            public DnsSecValidationResult ValidationResult { get; }

            public CacheRecordList(IReadOnlyCollection<DnsRecordBase> list, DnsSecValidationResult validationResult)
            {
                List = list;
                ValidationResult = validationResult;
            }
        }

        public class CacheKey
		{
			private readonly DomainName _name;
			private readonly RecordClass _recordClass;
			private readonly int _hashCode;
			private readonly RecordType _recordType;

			public CacheKey(DomainName name, RecordType recordType, RecordClass recordClass)
			{
				_name = name;
				_recordClass = recordClass;
				_recordType = recordType;

				_hashCode = name.GetHashCode() ^ (7 * (int) recordType) ^ (11 * (int) recordClass);
			}


			public override int GetHashCode()
			{
				return _hashCode;
			}

			public override bool Equals(object? obj)
			{
				CacheKey? other = obj as CacheKey;

				if (other == null)
					return false;

				return (_recordType == other._recordType) && (_recordClass == other._recordClass) && (_name.Equals(other._name));
			}

			public override string ToString()
			{
				return _name.ToString(true) + " " + _recordClass.ToShortString() + " " + _recordType.ToShortString();
			}
		}

		public class CacheValue
		{
			public DateTime ExpireDateUtc { get; }
			public CacheRecordList Records { get; }

			public CacheValue(CacheRecordList records, int timeToLive)
			{
				Records = records;
				ExpireDateUtc = DateTime.UtcNow.AddSeconds(timeToLive);
			}
		}

        public sealed class CachedItem
        {
            private readonly SemaphoreSlim _lock = new(1, 1);
            private readonly CancellationTokenSource _cancellationTokenSource = new();
            private Task? _task;

            public PoolCacheItemState State { get; private set; } = PoolCacheItemState.Pending;
            public CacheValue? Value { get; private set; }
            public Exception? Exception { get; private set; }

            public void SetSuccessAnsRelease(CacheValue item)
            {
                Console.WriteLine("Release");

                if (State == PoolCacheItemState.Success)
                {
                    _lock.Release();

                    return;
                }
                else if (State == PoolCacheItemState.Pending)
                {
                }
                else if (State == PoolCacheItemState.Failed)
                {
                }
                else
                {
                    _lock.Release();

                    throw new NotSupportedException($"State '{State}' of cached item not supported in current context");
                }

                _task = null;
                Value = item;
                State = PoolCacheItemState.Success;

                _lock.Release();
            }

            public void SetTask(Func<CancellationToken, Task> func)
            {
                if (State != PoolCacheItemState.Pending)
                    throw new NotSupportedException($"State '{State}' of cached item not supported in current context");

                _task = func(_cancellationTokenSource.Token);
            }

            public void SetFailedAndRelease(Exception exception)
            {
                Console.WriteLine("Release");

                if (State == PoolCacheItemState.Failed)
                {
                    _lock.Release();

                    return;
                }
                else if (State == PoolCacheItemState.Pending)
                {
                }
                else if (State == PoolCacheItemState.Success)
                {
                }
                else
                {
                    _lock.Release();

                    throw new NotSupportedException($"State '{State}' of cached item not supported in current context");
                }

                _task = null;

                if (CheckAll(exception, x => x is OperationCanceledException))
                {
                    State = PoolCacheItemState.Pending;
                }
                else
                {
                    Exception = exception;
                    State = PoolCacheItemState.Failed;
                }

                _lock.Release();
            }

            public void Reset()
            {
                Console.WriteLine("Reset");

                if (State == PoolCacheItemState.Pending)
                {
                    return;
                }
                else if (State == PoolCacheItemState.Failed)
                {
                }
                else if (State == PoolCacheItemState.Success)
                {
                }
                else
                {
                    throw new NotSupportedException($"State '{State}' of cached item not supported in current context");
                }

                try
                {
                    if (Value is IDisposable disposable)
                        disposable.Dispose();
                    else if (Value is IAsyncDisposable asyncDisposable)
                        asyncDisposable.DisposeAsync().GetAwaiter().GetResult();
                }
                finally
                {
                    _task = null;
                    Value = null;
                    State = PoolCacheItemState.Pending;
                }
            }

            public async Task ResetAsync()
            {
                Console.WriteLine("Reset");

                if (State == PoolCacheItemState.Pending)
                {
                    return;
                }
                else if (State == PoolCacheItemState.Failed)
                {
                }
                else if (State == PoolCacheItemState.Success)
                {
                }
                else
                {
                    throw new NotSupportedException($"State '{State}' of cached item not supported in current context");
                }

                try
                {
                    if (Value is IAsyncDisposable asyncDisposable)
                        await asyncDisposable.DisposeAsync();
                    else if (Value is IDisposable disposable)
                        disposable.Dispose();
                }
                finally
                {
                    _task = null;
                    Value = null;
                    State = PoolCacheItemState.Pending;
                }
            }

            public async Task ResetAndRelease()
            {
                Console.WriteLine("Release");

                if (State == PoolCacheItemState.Pending)
                {
                    _lock.Release();

                    return;
                }
                else if (State == PoolCacheItemState.Failed)
                {
                }
                else if (State == PoolCacheItemState.Success)
                {
                }
                else
                {
                    _lock.Release();

                    throw new NotSupportedException($"State '{State}' of cached item not supported in current context");
                }

                try
                {
                    if (Value is IAsyncDisposable asyncDisposable)
                        await asyncDisposable.DisposeAsync();
                    else if (Value is IDisposable disposable)
                        disposable.Dispose();
                }
                finally
                {
                    _task = null;
                    Value = null;
                    State = PoolCacheItemState.Pending;

                    _lock.Release();
                }
            }

            public Task WaitAsync(CancellationToken cancellationToken)
            {
                return _task!.WaitAsync(cancellationToken);
            }

            public void Lock()
            {
                _lock.Wait();

                Console.WriteLine("Lock");
            }

            public async Task LockAsync(CancellationToken cancellationToken)
            {
                await _lock.WaitAsync(cancellationToken);

                Console.WriteLine("Lock");
            }

            public void Release()
            {
                Console.WriteLine("Release");

                _lock.Release();
            }
        }

        private readonly ConcurrentDictionary<CacheKey, CachedItem> _cache = new();
        private int _disposing = 0;

        private static bool CheckAll(Exception self, Func<Exception, bool> func)
        {
            if (self is AggregateException aggregateException)
                return aggregateException.InnerExceptions.All(x => CheckAll(x, func));

            return func(self);
        }

        public CachedItem GetAndLock(CacheKey key)
        {
            if (_disposing == 1)
                throw new ObjectDisposedException("Object disposing");

            var cachedItem = _cache.GetOrAdd(key, (_) => new CachedItem());

            cachedItem.Lock();

            return cachedItem;
        }

        public async Task<CachedItem> GetAndLockAsync(CacheKey key, CancellationToken cancellationToken)
        {
            if (_disposing == 1)
                throw new ObjectDisposedException("Object disposing");

            var cachedItem = _cache.GetOrAdd(key, (_) => new CachedItem());

            await cachedItem.LockAsync(cancellationToken);

            return cachedItem;
        }

		public async Task RemoveExpiredItems(CancellationToken cancellationToken)
		{
			DateTime utcNow = DateTime.UtcNow;

			foreach (var kvp in _cache)
			{
                await kvp.Value.LockAsync(cancellationToken);

                if (kvp.Value.Value!.ExpireDateUtc < utcNow)
                    await kvp.Value.ResetAndRelease();
                else
                    kvp.Value.Release();
            }
		}
	}
}