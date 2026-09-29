import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  addAllowlist,
  listAlerts,
  listAllowlist,
  listBlocks,
  login,
  logout,
  me,
  removeAllowlist,
  unblockAddress,
} from "../client";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("login", () => {
  it("posts credentials and returns the user on success", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse(200, { id: "1", email: "a@b.com", role: "analyst" }));
    vi.stubGlobal("fetch", fetchMock);

    const user = await login("a@b.com", "secret-password");

    expect(user).toEqual({ id: "1", email: "a@b.com", role: "analyst" });
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/v1/auth/login");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      email: "a@b.com",
      password: "secret-password",
    });
  });

  it("raises an ApiError with the string detail on a 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(401, { detail: "Invalid email or password" })),
    );

    await expect(login("a@b.com", "wrong")).rejects.toMatchObject({
      status: 401,
      message: "Invalid email or password",
    });
  });

  it("extracts the first message from a pydantic validation error (422)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(422, {
          detail: [{ msg: "not a valid email address", type: "value_error" }],
        }),
      ),
    );

    await expect(login("bad", "x")).rejects.toMatchObject({
      status: 422,
      message: "not a valid email address",
    });
  });

  it("falls back to the status text when the body is not JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("<html>gateway down</html>", { status: 502, statusText: "Bad Gateway" }),
        ),
    );

    await expect(login("a@b.com", "x")).rejects.toBeInstanceOf(ApiError);
    await expect(login("a@b.com", "x")).rejects.toMatchObject({
      status: 502,
      message: "Bad Gateway",
    });
  });
});

describe("logout", () => {
  it("returns nothing on a 204", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })));

    await expect(logout()).resolves.toBeUndefined();
  });
});

describe("me", () => {
  it("returns the current user", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(200, { id: "1", email: "a@b.com", role: "admin" })),
    );

    await expect(me()).resolves.toEqual({ id: "1", email: "a@b.com", role: "admin" });
  });

  it("rejects on a 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(401, { detail: "Not authenticated" })),
    );

    await expect(me()).rejects.toMatchObject({ status: 401 });
  });
});

describe("listAlerts", () => {
  it("builds no query string when no params are given", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, []));
    vi.stubGlobal("fetch", fetchMock);

    await listAlerts();

    expect(fetchMock.mock.calls[0][0]).toBe("/v1/alerts");
  });

  it("encodes limit and rule into the query string", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, []));
    vi.stubGlobal("fetch", fetchMock);

    await listAlerts({ limit: 5, rule: "ssh-bruteforce" });

    expect(fetchMock.mock.calls[0][0]).toBe("/v1/alerts?limit=5&rule=ssh-bruteforce");
  });

  it("omits an empty rule filter", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, []));
    vi.stubGlobal("fetch", fetchMock);

    await listAlerts({ limit: 10, rule: "" });

    expect(fetchMock.mock.calls[0][0]).toBe("/v1/alerts?limit=10");
  });
});

describe("response API", () => {
  afterEach(() => vi.restoreAllMocks());

  function respond(status: number, body: unknown = null) {
    // A fresh Response per call: a body can only be read once.
    return vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () =>
        status === 204 ? new Response(null, { status }) : jsonResponse(status, body),
      );
  }

  it("lists blocks with a limit", async () => {
    const fetchMock = respond(200, []);
    await listBlocks(25);
    expect(fetchMock.mock.calls[0][0]).toBe("/v1/response/blocks?limit=25");
  });

  it("posts the address to unblock", async () => {
    const fetchMock = respond(204);
    await unblockAddress("45.83.64.10");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/v1/response/blocks/unblock");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ address: "45.83.64.10" });
  });

  it("encodes the network when removing an allowlist entry", async () => {
    const fetchMock = respond(204);
    await removeAllowlist("198.51.100.0/24");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/v1/response/allowlist?cidr=198.51.100.0%2F24");
    expect(init?.method).toBe("DELETE");
  });

  it("adds an allowlist entry", async () => {
    const fetchMock = respond(201, {});
    await addAllowlist("203.0.113.7", "home");
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      cidr: "203.0.113.7",
      note: "home",
    });
    await listAllowlist();
    expect(fetchMock.mock.calls[1][0]).toBe("/v1/response/allowlist");
  });
});
