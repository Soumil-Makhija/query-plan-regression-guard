SELECT id, customer_id, total_cents
FROM public.guard_orders
WHERE customer_id = %s
