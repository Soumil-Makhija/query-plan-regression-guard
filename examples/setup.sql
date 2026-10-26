-- Synthetic fixture only. Use a fresh, disposable database.
CREATE TABLE public.guard_orders (
  id integer PRIMARY KEY,
  customer_id integer NOT NULL,
  total_cents integer NOT NULL,
  padding text NOT NULL
);
INSERT INTO public.guard_orders
SELECT i, i % 10000, 100 + i % 9000, repeat('x', 80)
FROM generate_series(1, 50000) i;
CREATE INDEX guard_orders_customer_idx ON public.guard_orders(customer_id);
ANALYZE public.guard_orders;
