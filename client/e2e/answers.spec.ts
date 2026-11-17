import { expect, test, type Page } from '@playwright/test'
import { siteURL } from './env'
import { addToBasket, demoPassword, signIn } from './pages'
import { person, quiet, useRoles } from './roles'

// How the app treats what it is given: a visitor's basket survives signing
// in, a lapsed person's does not, an unusable Fetch Accounts answer never becomes a session, and an
// error code the app does not know is shown in plain words. The odd answers
// are written over real ones in the browser, as no Fetch service sends them.
test.describe.serial('Answers the app is given', () => {
  useRoles()

  test('a visitor keeps the basket and address they filled in when they sign in', async ({ browser }) => {
    const visitor = await person(browser, null)
    await addToBasket(visitor, siteURL, 'MER-005', 'Full Cream Milk 1 L')
    await visitor.goto(siteURL + '/checkout', { waitUntil: 'networkidle' })
    await signIn(visitor, siteURL, 'customer2@fetch.test')
    const kept = await visitor.evaluate(() => sessionStorage.getItem('fetch.basket'))
    expect(kept).toContain('Full Cream Milk 1 L')
    await visitor.goto(siteURL + '/checkout', { waitUntil: 'networkidle' })
    await expect(visitor.getByText('Full Cream Milk 1 L').first()).toBeVisible()
    await visitor.context().close()
  })

  test('a session that lapsed before the page loaded leaves its basket to nobody', async ({ browser }) => {
    const customer = await person(browser, null)
    await signIn(customer, siteURL, 'customer2@fetch.test')
    await addToBasket(customer, siteURL, 'MER-005', 'Full Cream Milk 1 L')
    await expect.poll(() => customer.evaluate(() => sessionStorage.getItem('fetch.basket'))).toContain('Full Cream Milk 1 L')
    await customer.evaluate(() => {
      const stored = JSON.parse(sessionStorage.getItem('fetch.session') ?? '{}') as Record<string, unknown>
      sessionStorage.setItem('fetch.session', JSON.stringify({ ...stored, expiresAt: Date.now() - 1000 }))
    })
    await customer.reload({ waitUntil: 'networkidle' })
    expect(await customer.evaluate(() => sessionStorage.getItem('fetch.session'))).toBeNull()
    expect(await customer.evaluate(() => sessionStorage.getItem('fetch.basket'))).toBeNull()
    await customer.context().close()
  })

  test('a sign-in answer with an unreadable expiry or a foreign home page is refused, and no refresh follows', async ({ browser }) => {
    for (const change of [{ expires_at: 'soon' }, { home: 'javascript:alert(1)' }]) {
      const visitor = await person(browser, null)
      await visitor.route('**/accounts/login', async (route) => {
        const response = await route.fetch()
        const answer = (await response.json()) as { expires_at: string; user: Record<string, unknown> }
        if ('home' in change) answer.user.home = change.home
        else answer.expires_at = change.expires_at
        await route.fulfill({ response, json: answer })
      })
      await visitor.goto(siteURL + '/signin', { waitUntil: 'networkidle' })
      await visitor.getByLabel('Email').fill('customer1@fetch.test')
      await visitor.getByLabel('Password', { exact: true }).fill(demoPassword)
      await visitor.getByRole('button', { name: 'Sign in', exact: true }).click()
      await expect(visitor.getByRole('alert').filter({ hasText: 'Fetch couldn’t do this.' })).toBeVisible()
      await expect(visitor.getByRole('heading', { level: 1, name: 'Sign in to Fetch' })).toBeVisible()
      expect(await visitor.evaluate(() => sessionStorage.getItem('fetch.session'))).toBeNull()
      expect((await quiet(visitor)).filter((entry) => entry.startsWith('POST /accounts/'))).toEqual([])
      await visitor.context().close()
    }
  })

  test('an error code the app does not know is shown in plain words, whoever answers', async ({ browser }) => {
    const visitor = await person(browser, null)
    const answer = async (page: Page, status: number, headers: Record<string, string>) => {
      await page.route('**/*', (route) =>
        route.request().resourceType() === 'fetch' && route.request().method() === 'GET'
          ? route.fulfill({ status, headers, json: { error: 'constructor' } })
          : route.continue(),
      )
      await page.goto(siteURL + '/store/MER-005', { waitUntil: 'networkidle' })
      await page.unroute('**/*')
    }
    await answer(visitor, 400, {})
    await expect(visitor.getByRole('alert').filter({ hasText: 'Fetch answered with an error (400).' }).first()).toBeVisible()
    await answer(visitor, 409, { 'X-Service': 'constructor' })
    await expect(visitor.getByRole('alert').filter({ hasText: 'Fetch couldn’t do this.' }).first()).toContainText('constructor')
    await visitor.context().close()
  })
})
