// Billing routes — Stripe payment integration for plan upgrades
const express = require('express');
const router = express.Router();
const { API_PLANS, createAPIKey } = require('../middleware/auth');

// Price map: plan name → env var for Stripe Price ID
const PLAN_PRICES = {
  starter: { envVar: 'STRIPE_STARTER_PRICE_ID', amount: 900, name: 'Starter' },
  pro: { envVar: 'STRIPE_PRO_PRICE_ID', amount: 1999, name: 'Pro' },
  enterprise: { envVar: 'STRIPE_ENTERPRISE_PRICE_ID', amount: 9999, name: 'Enterprise' }
};

// Lazy-load Stripe to allow graceful degradation
function getStripe() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) return null;
  return require('stripe')(key);
}

function billingNotConfigured(res) {
  return res.status(503).json({
    error: 'Billing not configured',
    message: 'Stripe billing is not enabled on this instance. Contact the administrator.'
  });
}

// ─── POST /checkout — Create a Stripe Checkout Session ───────────────────────
router.post('/checkout', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return billingNotConfigured(res);

  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Provide your API key in X-API-Key header to upgrade your plan'
      });
    }

    const { plan } = req.body;
    if (!plan || !PLAN_PRICES[plan]) {
      return res.status(400).json({
        error: 'Invalid plan',
        message: 'Specify "plan": "pro" or "plan": "enterprise"',
        availablePlans: Object.keys(PLAN_PRICES)
      });
    }

    const priceId = process.env[PLAN_PRICES[plan].envVar];
    if (!priceId) {
      return res.status(503).json({
        error: 'Price not configured',
        message: `Stripe price ID for ${plan} plan is not set`
      });
    }

    const appUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
    const userId = req.user.id;

    // Look up user email for Stripe
    const user = await req.db.get('SELECT email, name FROM users WHERE user_id = ?', [userId]);

    // Check if user already has a Stripe customer ID
    let customerId;
    const existingCustomer = await req.db.get(
      'SELECT stripe_customer_id FROM users WHERE user_id = ? AND stripe_customer_id IS NOT NULL',
      [userId]
    );

    if (existingCustomer?.stripe_customer_id) {
      customerId = existingCustomer.stripe_customer_id;
    } else if (user?.email) {
      // Create Stripe customer
      const customer = await stripe.customers.create({
        email: user.email,
        name: user.name || undefined,
        metadata: { userId }
      });
      customerId = customer.id;
      // Store customer ID (add column if missing)
      await ensureStripeColumns(req.db);
      await req.db.run('UPDATE users SET stripe_customer_id = ? WHERE user_id = ?', [customerId, userId]);
    }

    const sessionParams = {
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${appUrl}/?billing=success&plan=${plan}`,
      cancel_url: `${appUrl}/?billing=cancelled`,
      metadata: { userId, plan },
      payment_method_types: ['card'],
      ...(customerId ? { customer: customerId } : {})
    };

    const session = await stripe.checkout.sessions.create(sessionParams);

    res.json({
      url: session.url,
      sessionId: session.id,
      plan,
      message: `Redirect user to the URL to complete ${PLAN_PRICES[plan].name} subscription`
    });
  } catch (error) {
    console.error('Checkout error:', error);
    res.status(500).json({ error: 'Checkout failed', message: error.message });
  }
});

// ─── POST /webhook — Stripe webhook handler ──────────────────────────────────
router.post('/webhook', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(200).send('Billing not configured — ignoring');

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    if (webhookSecret && sig) {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      // If no webhook secret, parse body directly (dev mode)
      event = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    const db = req.db;

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const userId = session.metadata?.userId;
        const plan = session.metadata?.plan;

        if (userId && plan && API_PLANS[plan]) {
          await ensureStripeColumns(db);

          // Store/update Stripe customer ID
          if (session.customer) {
            await db.run('UPDATE users SET stripe_customer_id = ? WHERE user_id = ?', [session.customer, userId]);
          }

          // Update user plan
          await db.run('UPDATE users SET plan = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?', [plan, userId]);

          // Update all active API keys to new plan limits
          const planConfig = API_PLANS[plan];
          await db.run(
            'UPDATE api_keys SET plan = ?, daily_limit = ?, monthly_limit = ? WHERE user_id = ? AND is_active = TRUE',
            [plan, planConfig.dailyLimit, planConfig.monthlyLimit, userId]
          );

          // Store subscription ID
          if (session.subscription) {
            await db.run('UPDATE users SET stripe_subscription_id = ? WHERE user_id = ?', [session.subscription, userId]);
          }

          console.log(`✅ User ${userId} upgraded to ${plan}`);
        }
        break;
      }

      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const customerId = subscription.customer;
        const status = subscription.status;

        await ensureStripeColumns(db);
        const subUser = await db.get('SELECT user_id FROM users WHERE stripe_customer_id = ?', [customerId]);

        if (subUser) {
          if (status === 'active') {
            // Determine plan from price — check metadata first, then price lookup
            let newPlan = subscription.metadata?.plan;
            if (!newPlan && subscription.items?.data?.length > 0) {
              const priceId = subscription.items.data[0].price?.id;
              if (priceId === process.env.STRIPE_PRO_PRICE_ID) newPlan = 'pro';
              else if (priceId === process.env.STRIPE_ENTERPRISE_PRICE_ID) newPlan = 'enterprise';
            }
            if (newPlan && API_PLANS[newPlan]) {
              const planConfig = API_PLANS[newPlan];
              await db.run('UPDATE users SET plan = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?', [newPlan, subUser.user_id]);
              await db.run(
                'UPDATE api_keys SET plan = ?, daily_limit = ?, monthly_limit = ? WHERE user_id = ? AND is_active = TRUE',
                [newPlan, planConfig.dailyLimit, planConfig.monthlyLimit, subUser.user_id]
              );
              console.log(`🔄 User ${subUser.user_id} plan updated to ${newPlan}`);
            }
          } else if (status === 'past_due' || status === 'unpaid') {
            console.log(`⚠️ User ${subUser.user_id} subscription status: ${status}`);
          }
        }
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const customerId = invoice.customer;

        await ensureStripeColumns(db);
        const failedUser = await db.get('SELECT user_id FROM users WHERE stripe_customer_id = ?', [customerId]);
        if (failedUser) {
          console.log(`❌ Payment failed for user ${failedUser.user_id}, invoice ${invoice.id}`);
          // Don't downgrade immediately — Stripe retries. Downgrade happens on subscription.deleted
        }
        break;
      }

      case 'customer.subscription.deleted': {
        // Deactivate API keys when subscription is cancelled — no free tier
        const subscription = event.data.object;
        const customerId = subscription.customer;

        // Find user by Stripe customer ID
        await ensureStripeColumns(req.db);
        const user = await db.get('SELECT user_id FROM users WHERE stripe_customer_id = ?', [customerId]);

        if (user) {
          // Deactivate all API keys — they need to resubscribe
          await db.run('UPDATE users SET plan = ?, stripe_subscription_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?', ['expired', user.user_id]);
          await db.run(
            'UPDATE api_keys SET is_active = FALSE WHERE user_id = ?',
            [user.user_id]
          );
          console.log(`⛔ User ${user.user_id} subscription cancelled — API keys deactivated`);
        }
        break;
      }

      default:
        // Unhandled event type — that's fine
        break;
    }

    res.json({ received: true });
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// ─── GET /portal — Create Stripe Customer Portal session ─────────────────────
router.get('/portal', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return billingNotConfigured(res);

  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Provide your API key in X-API-Key header'
      });
    }

    await ensureStripeColumns(req.db);
    const user = await req.db.get('SELECT stripe_customer_id FROM users WHERE user_id = ?', [req.user.id]);

    if (!user?.stripe_customer_id) {
      return res.status(404).json({
        error: 'No billing account',
        message: 'You don\'t have an active subscription. Use POST /billing/checkout to subscribe.'
      });
    }

    const appUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: appUrl
    });

    res.json({
      url: portalSession.url,
      message: 'Redirect to this URL to manage your subscription'
    });
  } catch (error) {
    console.error('Portal error:', error);
    res.status(500).json({ error: 'Portal creation failed', message: error.message });
  }
});

// ─── GET /status — Current plan and usage stats ──────────────────────────────
router.get('/status', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Provide your API key in X-API-Key header'
      });
    }

    const db = req.db;
    const userId = req.user.id;

    const user = await db.get('SELECT email, name, plan, created_at FROM users WHERE user_id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get usage stats
    const now = new Date();
    const today = now.toISOString().split('T')[0];
    const thisMonth = now.toISOString().substring(0, 7);

    const dailyUsage = await db.get(
      'SELECT COUNT(*) as count FROM api_usage WHERE api_key IN (SELECT key_id FROM api_keys WHERE user_id = ?) AND DATE(timestamp) = ?',
      [userId, today]
    );

    const monthlyUsage = await db.get(
      'SELECT COUNT(*) as count FROM api_usage WHERE api_key IN (SELECT key_id FROM api_keys WHERE user_id = ?) AND strftime(\'%Y-%m\', timestamp) = ?',
      [userId, thisMonth]
    );

    const planConfig = API_PLANS[user.plan] || API_PLANS.free;

    res.json({
      user: {
        email: user.email,
        name: user.name,
        plan: user.plan,
        planName: planConfig.name,
        memberSince: user.created_at
      },
      usage: {
        today: dailyUsage?.count || 0,
        thisMonth: monthlyUsage?.count || 0
      },
      limits: {
        daily: planConfig.dailyLimit === -1 ? 'unlimited' : planConfig.dailyLimit,
        monthly: planConfig.monthlyLimit === -1 ? 'unlimited' : planConfig.monthlyLimit
      },
      features: planConfig.features,
      billing: {
        stripeConfigured: !!getStripe(),
        canUpgrade: user.plan !== 'enterprise',
        checkoutEndpoint: 'POST /billing/checkout',
        portalEndpoint: 'GET /billing/portal'
      }
    });
  } catch (error) {
    console.error('Billing status error:', error);
    res.status(500).json({ error: 'Failed to get billing status', message: error.message });
  }
});

// ─── Helper: ensure Stripe columns exist on users table ──────────────────────
async function ensureStripeColumns(db) {
  try {
    await db.run('ALTER TABLE users ADD COLUMN stripe_customer_id TEXT');
  } catch (e) {
    // Column already exists — ignore
  }
  try {
    await db.run('ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT');
  } catch (e) {
    // Column already exists — ignore
  }
}

// ─── POST /web-checkout — Browser-friendly checkout (no API key needed) ──────
// Creates or finds user account, then creates Stripe Checkout session
router.post('/web-checkout', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return billingNotConfigured(res);

  try {
    const { plan, email, name } = req.body;

    if (!plan || !PLAN_PRICES[plan]) {
      return res.status(400).json({
        error: 'Invalid plan',
        message: 'Specify "plan": "pro" or "plan": "enterprise"',
        availablePlans: Object.keys(PLAN_PRICES)
      });
    }

    if (!email || !name) {
      return res.status(400).json({
        error: 'Missing fields',
        message: 'Both "email" and "name" are required'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const priceId = process.env[PLAN_PRICES[plan].envVar];
    if (!priceId) {
      return res.status(503).json({
        error: 'Price not configured',
        message: `Stripe price ID for ${plan} plan is not set`
      });
    }

    const db = req.db;
    const crypto = require('crypto');

    // Find or create user
    let user = await db.get('SELECT user_id, stripe_customer_id FROM users WHERE email = ?', [email]);
    let userId;

    if (user) {
      userId = user.user_id;
    } else {
      // Create user account
      userId = crypto.randomUUID();
      await db.run(
        `CREATE TABLE IF NOT EXISTS users (
          user_id TEXT PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL,
          plan TEXT DEFAULT 'free',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`
      );
      await db.run(
        'INSERT INTO users (user_id, email, name, plan) VALUES (?, ?, ?, ?)',
        [userId, email, name, 'starter']
      );
      // Create starter API key for them (activated after Stripe payment)
      const { createAPIKey: createKey } = require('../middleware/auth');
      await createKey(db, userId, 'starter');
    }

    await ensureStripeColumns(db);

    // Find or create Stripe customer
    let customerId = user?.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email,
        name,
        metadata: { userId }
      });
      customerId = customer.id;
      await db.run('UPDATE users SET stripe_customer_id = ? WHERE user_id = ?', [customerId, userId]);
    }

    const appUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customerId,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${appUrl}/pricing.html?billing=success&plan=${plan}`,
      cancel_url: `${appUrl}/pricing.html?billing=cancelled`,
      metadata: { userId, plan },
      allow_promotion_codes: true,
      payment_method_types: ['card']
    });

    res.json({
      url: session.url,
      sessionId: session.id,
      plan,
      message: `Redirect to URL to complete ${PLAN_PRICES[plan].name} subscription`
    });
  } catch (error) {
    console.error('Web checkout error:', error);
    res.status(500).json({ error: 'Checkout failed', message: error.message });
  }
});

module.exports = router;
