import asyncio
import json
import unittest

from codex_ssh.broker import Broker, BrokerError
from codex_ssh.runner import SSHResult


ORIGIN = "https://bridge.example.ts.net"
SPEC = {"host": "example-host", "command": "id", "authentication": "password", "sudo": True}


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.release = asyncio.Event()
        self.cancelled = False
        self.error = None

    async def run_secure(self, **kwargs):
        self.calls.append(dict(kwargs))
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        if self.error:
            raise self.error
        return SSHResult(kwargs["host"], f"output {kwargs['ssh_password']}", f"error {kwargs['sudo_password']}", 0, False, False, False)


class BrokerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.runner = FakeRunner()
        self.broker = Broker(self.runner, ORIGIN)
        self.session = "a" * 64

    async def asyncTearDown(self):
        await self.broker.shutdown()

    async def new_form(self, spec=None):
        public = await self.broker.create(dict(SPEC if spec is None else spec))
        _, _, csrf = await self.broker.page(public["operation_id"], self.session)
        return public["operation_id"], csrf

    async def finish(self, operation_id):
        self.runner.release.set()
        for _ in range(30):
            await asyncio.sleep(0)
            public = await self.broker.status(operation_id)
            if public["status"] != "running":
                return public
        self.fail("runner never completed")

    async def test_create_is_immutable_and_does_not_execute(self):
        spec = dict(SPEC)
        public = await self.broker.create(spec)
        spec["command"] = "changed"
        _, saved, _ = await self.broker.page(public["operation_id"], self.session)
        self.assertEqual(saved["command"], "id")
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(set(public), {"operation_id", "url", "status"})
        self.assertEqual(public["status"], "waiting_for_user")

    async def test_create_rejects_secrets_invalid_and_extra_fields(self):
        for change in ({"ssh_password": "secret"}, {"sudo_password": "secret"}, {"unknown": 1}, {"host": "-proxy"}, {"command": "a\nb"}, {"sudo": "true"}, {"authentication": "auto"}, {"port": True}):
            with self.subTest(change=change):
                with self.assertRaises(BrokerError):
                    await self.broker.create(dict(SPEC, **change))
        self.assertEqual(len(self.broker._jobs), 0)

    async def test_csrf_bound_to_cookie_operation_and_latest_form(self):
        operation, csrf = await self.new_form()
        other, _ = await self.new_form()
        for ident, session, token in ((operation, "b" * 64, csrf), (other, self.session, csrf), (operation, self.session, "f" * 64)):
            with self.assertRaises(BrokerError):
                await self.broker.submit(ident, session, token, ssh_password="secret1", sudo_password="secret2")
        _, _, newer = await self.broker.page(operation, self.session)
        with self.assertRaises(BrokerError):
            await self.broker.submit(operation, self.session, csrf, ssh_password="secret1", sudo_password="secret2")
        self.assertNotEqual(csrf, newer)
        self.assertEqual(self.runner.calls, [])

    async def test_single_use_and_secret_redaction(self):
        operation, csrf = await self.new_form()
        await self.broker.submit(operation, self.session, csrf, ssh_password="secret-one", sudo_password="secret-two")
        with self.assertRaises(BrokerError):
            await self.broker.submit(operation, self.session, csrf, ssh_password="secret-one", sudo_password="secret-two")
        public = await self.finish(operation)
        serialized = json.dumps(public)
        self.assertNotIn("secret-one", serialized)
        self.assertNotIn("secret-two", serialized)
        self.assertEqual(public["status"], "completed")
        self.assertEqual(len(self.runner.calls), 1)
        self.assertNotIn("ssh_password", self.broker._jobs[operation].spec)

    async def test_redaction_expansion_keeps_output_bounded(self):
        class LargeRunner:
            async def run_secure(self, **kwargs):
                return SSHResult(kwargs["host"], "x" * 65_536, "tail", 0, False, False, False)

        self.broker._runner = LargeRunner()
        operation, csrf = await self.new_form()
        await self.broker.submit(operation, self.session, csrf, ssh_password="x", sudo_password="dummy-sudo")
        public = await self.finish(operation)
        result = public["result"]
        self.assertLessEqual(len(result["stdout"].encode()) + len(result["stderr"].encode()), 65_536)
        self.assertTrue(result["output_truncated"])
        self.assertEqual(result["host"], SPEC["host"])

    async def test_invalid_password_does_not_consume_form(self):
        operation, csrf = await self.new_form()
        for value in (None, "", "bad\nvalue", "bad\0value", "x" * 4097):
            with self.assertRaises(BrokerError):
                await self.broker.submit(operation, self.session, csrf, ssh_password=value, sudo_password="ok")
        await self.broker.submit(operation, self.session, csrf, ssh_password="valid", sudo_password="ok")

    async def test_key_mode_rejects_unneeded_password(self):
        operation, csrf = await self.new_form({"host": "example-host", "command": "id"})
        with self.assertRaises(BrokerError):
            await self.broker.submit(operation, self.session, csrf, ssh_password="unexpected")
        await self.broker.submit(operation, self.session, csrf)

    async def test_capacity_preserves_form_and_cancellation_frees_slot(self):
        self.broker._max_running = 1
        first, csrf = await self.new_form()
        await self.broker.submit(first, self.session, csrf, ssh_password="secret", sudo_password="secret")
        second, second_csrf = await self.new_form()
        with self.assertRaises(BrokerError) as caught:
            await self.broker.submit(second, self.session, second_csrf, ssh_password="secret", sudo_password="secret")
        self.assertEqual(caught.exception.status_code, 429)
        # This deliberately cancels before the scheduled coroutine's first turn.
        self.assertEqual((await self.broker.cancel(first))["status"], "cancelled")
        self.assertEqual(self.broker._running, 0)
        await self.broker.submit(second, self.session, second_csrf, ssh_password="secret", sudo_password="secret")

    async def test_running_cancel_reaps_runner(self):
        operation, csrf = await self.new_form()
        await self.broker.submit(operation, self.session, csrf, ssh_password="secret", sudo_password="secret")
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual((await self.broker.cancel(operation))["status"], "cancelled")
        self.assertTrue(self.runner.cancelled)

    async def test_browser_running_cancel_uses_fresh_csrf(self):
        operation, csrf = await self.new_form()
        await self.broker.submit(operation, self.session, csrf, ssh_password="secret", sudo_password="secret")
        with self.assertRaises(BrokerError):
            await self.broker.cancel(operation, session=self.session, csrf=csrf)
        _, _, cancel_csrf = await self.broker.page(operation, self.session)
        self.assertNotEqual(csrf, cancel_csrf)
        public = await self.broker.cancel(operation, session=self.session, csrf=cancel_csrf)
        self.assertEqual(public["status"], "cancelled")

    async def test_pending_and_result_expire_without_polling(self):
        await self.broker.shutdown()
        self.broker = Broker(self.runner, ORIGIN, pending_ttl=0.01, result_ttl=0.01)
        await self.broker.start()
        operation, csrf = await self.new_form()
        await asyncio.sleep(0.015)
        with self.assertRaises(BrokerError):
            await self.broker.submit(operation, self.session, csrf, ssh_password="secret", sudo_password="secret")
        await asyncio.sleep(0.03)
        self.assertNotIn(operation, self.broker._jobs)

    async def test_bounded_jobs(self):
        self.broker._max_jobs = 1
        await self.broker.create(SPEC)
        with self.assertRaises(BrokerError) as caught:
            await self.broker.create(SPEC)
        self.assertEqual(caught.exception.status_code, 429)

    async def test_failures_do_not_disclose_exception_or_secret(self):
        self.runner.error = RuntimeError("PRIVATE secret detail")
        operation, csrf = await self.new_form()
        await self.broker.submit(operation, self.session, csrf, ssh_password="secret", sudo_password="other")
        public = await self.finish(operation)
        self.assertEqual(public["status"], "failed")
        self.assertNotIn("PRIVATE", json.dumps(public))
        self.assertNotIn("secret", json.dumps(public))

    async def test_shutdown_cancels_and_discards_all_state(self):
        operation, csrf = await self.new_form()
        await self.broker.submit(operation, self.session, csrf, ssh_password="secret", sudo_password="secret")
        await self.broker.shutdown()
        self.assertEqual(self.broker._jobs, {})
        self.assertEqual(self.broker._running, 0)
        with self.assertRaises(BrokerError):
            await self.broker.create(SPEC)

    async def test_browser_cancel_requires_csrf_and_is_single_use(self):
        operation, csrf = await self.new_form()
        with self.assertRaises(BrokerError):
            await self.broker.cancel(operation, session="bad", csrf=csrf)
        self.assertEqual((await self.broker.cancel(operation, session=self.session, csrf=csrf))["status"], "cancelled")
        with self.assertRaises(BrokerError):
            await self.broker.submit(operation, self.session, csrf, ssh_password="secret", sudo_password="secret")


if __name__ == "__main__":
    unittest.main()
