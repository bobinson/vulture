# Feature 0101 held-out (LLD 4.6), CWE-770 in Elixir, a language no 0101 probe or
# lexicon touched. A table, set or queue that grows once per packet, line or message
# from a peer, with no cap, is unbounded; growth over a finite in-memory collection,
# or growth checked against a maximum, is not. Every identifier is invented.
# HELD-OUT-TOKENS: ets, gen_tcp, repeatedly, stdio, MapSet, Agent

defmodule Relay.Collector do
  @max_rows 10_000

  def drain_socket(socket, table) do
    for packet <- Stream.repeatedly(fn -> :gen_tcp.recv(socket, 0) end) do
      # EXPECT-NEXT: finding
      :ets.insert(table, {packet, true})
    end
  end

  def remember_lines(store) do
    for line <- IO.stream(:stdio, :line) do
      # EXPECT-NEXT: finding
      Agent.update(store, fn seen -> MapSet.put(seen, line) end)
    end
  end

  def mailbox_loop(pending) do
    receive do
      {:chunk, data} ->
        # EXPECT-NEXT: clean held-out-miss (concept: finding)
        mailbox_loop(:queue.in(data, pending))
    end
  end

  def drain_capped(socket, table) do
    for packet <- Stream.repeatedly(fn -> :gen_tcp.recv(socket, 0) end) do
      if :ets.info(table, :size) < @max_rows do
        # EXPECT-NEXT: finding held-out-miss (concept: clean)
        :ets.insert(table, {packet, true})
      end
    end
  end

  def squares(table) do
    for n <- 1..10 do
      # EXPECT-NEXT: clean
      :ets.insert(table, {n, n * n})
    end
  end

  def index_rows(table, body) do
    for row <- String.split(body, "\n") do
      # EXPECT-NEXT: clean
      :ets.insert(table, {row, true})
    end
  end
end
