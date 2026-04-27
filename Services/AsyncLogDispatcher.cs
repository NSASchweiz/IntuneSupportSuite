using System.Collections.Concurrent;
using System.Threading;

namespace DapIntuneSupportSuite.Services;

public static class AsyncLogDispatcher
{
    private static readonly BlockingCollection<Action> Queue = new();
    private static readonly Thread Worker;
    private static int _isShuttingDown;

    static AsyncLogDispatcher()
    {
        Worker = new Thread(ProcessQueue)
        {
            IsBackground = true,
            Name = "IntuneSupportSuite-AsyncLogDispatcher"
        };
        Worker.Start();
    }

    public static void Enqueue(Action writeAction)
    {
        if (writeAction is null)
        {
            return;
        }

        if (Volatile.Read(ref _isShuttingDown) == 1)
        {
            try
            {
                writeAction();
            }
            catch
            {
                // Logging darf die App nicht destabilisieren.
            }
            return;
        }

        try
        {
            Queue.Add(writeAction);
        }
        catch
        {
            try
            {
                writeAction();
            }
            catch
            {
                // Logging darf die App nicht destabilisieren.
            }
        }
    }

    public static void Flush(TimeSpan timeout)
    {
        if (Volatile.Read(ref _isShuttingDown) == 1)
        {
            return;
        }

        using var barrier = new ManualResetEventSlim(false);
        Enqueue(() => barrier.Set());
        barrier.Wait(timeout);
    }

    public static void Shutdown(TimeSpan timeout)
    {
        if (Interlocked.Exchange(ref _isShuttingDown, 1) == 1)
        {
            return;
        }

        Flush(timeout);
        Queue.CompleteAdding();
        Worker.Join(timeout);
    }

    private static void ProcessQueue()
    {
        foreach (var action in Queue.GetConsumingEnumerable())
        {
            try
            {
                action();
            }
            catch
            {
                // Logging darf die App nicht destabilisieren.
            }
        }
    }
}
