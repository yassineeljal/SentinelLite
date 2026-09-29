import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, listAlerts, login, logout, me } from "../client";

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
