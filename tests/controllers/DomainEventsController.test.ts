import { EventEmitter } from 'events';
import { Request, Response } from 'express';

const mockSubscribe = jest.fn();
const mockUnsubscribe = jest.fn().mockResolvedValue(undefined);
const mockQuit = jest.fn().mockResolvedValue(undefined);
const mockConnect = jest.fn().mockResolvedValue(undefined);

const mockSubscriber = {
   connect: mockConnect,
   subscribe: mockSubscribe,
   unsubscribe: mockUnsubscribe,
   quit: mockQuit,
};

jest.mock('../../src/services/DomainEventPublisher', () => ({
   DomainEventPublisher: {
      getInstance: () => ({
         createSubscriber: () => mockSubscriber,
      }),
      channel: () => 'sse:auth:cache-events',
   },
}));

jest.mock('../../src/utils/logger', () => ({
   appLogger: { warn: jest.fn() },
   sseLogger: { info: jest.fn(), warn: jest.fn() },
}));

import { DomainEventsController } from '../../src/controllers/DomainEventsController';
import { CACHE_INVALIDATE_SSE_EVENT } from '../../src/types/domainCacheEvents';

function createMockResponse(): Response & EventEmitter {
   const res = new EventEmitter() as Response & EventEmitter;
   const headers: Record<string, string> = {};
   res.setHeader = jest.fn((key: string, value: string) => {
      headers[key] = value;
      return res;
   });
   res.write = jest.fn();
   res.status = jest.fn().mockReturnValue(res);
   res.json = jest.fn().mockReturnValue(res);
   (res as Response & { flushHeaders?: () => void }).flushHeaders = jest.fn();
   (res as Response & { _headers: Record<string, string> })._headers = headers;
   return res;
}

describe('DomainEventsController', () => {
   beforeEach(() => {
      jest.useFakeTimers();
      mockSubscribe.mockClear();
      mockUnsubscribe.mockClear();
      mockQuit.mockClear();
      mockConnect.mockClear();
   });

   afterEach(() => {
      jest.useRealTimers();
   });

   it('returns 401 when user is not authenticated', async () => {
      const controller = new DomainEventsController();
      const req = {} as Request;
      const res = createMockResponse();

      await controller.streamCacheEvents(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
   });

   it('sets SSE headers and forwards Redis messages as cache-invalidate events', async () => {
      const controller = new DomainEventsController();
      const req = { user: { id: 'user-1' } } as Request & { user: { id: string } };
      const res = createMockResponse();

      await controller.streamCacheEvents(req, res);

      expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/event-stream');
      expect(res.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-cache');
      expect(res.setHeader).toHaveBeenCalledWith('Connection', 'keep-alive');
      expect(mockConnect).toHaveBeenCalled();
      expect(mockSubscribe).toHaveBeenCalledWith('sse:auth:cache-events', expect.any(Function));

      const onMessage = mockSubscribe.mock.calls[0][1] as (message: string) => void;
      const payload = {
         version: 1,
         service: 'auth',
         resource: 'author',
         action: 'created',
         id: 'a1',
         queryKeys: [['authors']],
         timestamp: '2026-06-13T12:00:00.000Z',
      };
      onMessage(JSON.stringify(payload));

      expect(res.write).toHaveBeenCalledWith(`event: ${CACHE_INVALIDATE_SSE_EVENT}\n`);
      expect(res.write).toHaveBeenCalledWith(`data: ${JSON.stringify(payload)}\n\n`);
   });

   it('writes heartbeat comments every 30s and cleans up on close', async () => {
      const controller = new DomainEventsController();
      const req = { user: { id: 'user-1' } } as Request & { user: { id: string } };
      const res = createMockResponse();

      await controller.streamCacheEvents(req, res);

      jest.advanceTimersByTime(30_000);
      expect(res.write).toHaveBeenCalledWith(': heartbeat\n\n');

      res.emit('close');
      expect(mockUnsubscribe).toHaveBeenCalledWith('sse:auth:cache-events');
      expect(mockQuit).toHaveBeenCalled();
   });
});
