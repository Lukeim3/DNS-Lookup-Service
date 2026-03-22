package ca.ubc.cs.cs317.dnslookup;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.naming.spi.ResolveResult;

import static ca.ubc.cs.cs317.dnslookup.DNSMessage.MAX_DNS_MESSAGE_LENGTH;

public class DNSLookupService {

    public static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    private static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new Random();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param verbose    A DNSVerbosePrinter listener object with methods to be called at key events in the query
     *                   processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Answers one question.  If there are valid (not expired) results in the cache, returns these results.
     * Otherwise it chooses the best nameserver to query, retrieves results from that server
     * (using individualQueryProcess which adds all the results to the cache) and repeats until either:
     *   the cache contains an answer to the query, or
     *   the cache contains an answer to the query that is a CNAME record rather than the requested type, or
     *   every "best" nameserver in the cache has already been tried.
     *
     *  @param question Host name and record type/class to be used for the query.
     */
    public Collection<ResourceRecord> iterativeQuery(DNSQuestion question)
            throws DNSErrorException {
        Set<ResourceRecord> ans = new HashSet<>();
        /* Access the cache to get best name servers,
         * individual query process each one
         */
        List<ResourceRecord> results = cache.getCachedResults(question);
        if (results.isEmpty()) {
            for (ResourceRecord ns : cache.filterByKnownIPAddress(cache.getBestNameservers(question))) {

                Set<ResourceRecord> rr = individualQueryProcess(question, ns.getInetResult()); //adds all resoucre records to cache
                
              //couldn't get the iterative query to get address of Cname


               
                for (ResourceRecord rans : cache.getCachedResults(question)) {
                   
                    if (rans.getQuestion().equals(question) ) {
                        ans.add(rans);
                    
                    }
                       
                }

                if (!ans.isEmpty()) {
                    return ans;
                 
                } else {
                    
                    Collection<ResourceRecord> r2 = iterativeQuery(question);
                    if (r2.isEmpty()) {
                        for (ResourceRecord r : rr) {
                            iterativeQuery(new DNSQuestion(r.getTextResult(), question.getRecordType(),question.getRecordClass()));
                        }
                        return iterativeQuery(question);

                    } else {
                        return r2;
                    }
                }
            }
            return ans;
        } else {
            
            return results;

        }

 

         /* 
                   List<ResourceRecord> results = cache.getCachedResults(question);
        if (results.isEmpty()) {
            for (ResourceRecord ns : cache.filterByKnownIPAddress(cache.getBestNameservers(question))) {

                Set<ResourceRecord> rr = individualQueryProcess(question, ns.getInetResult()); //adds all resoucre records to cache

               //determine if cname -> check yahoo example
               for (ResourceRecord r : rr) {
                    if (r.getRecordType().getCode() == 5) {
                        
                        return iterativeQuery(question); //return to  result following cname
                    }
               }
                if (containsAnswer(rr, question)) {
                    return iterativeQuery(question); 
                } else if (rr == null) {
                    continue;
                } else {
                       //maybe use cached answer
                    return iterativeQuery(question); 
                }
            }
        } else {
            
            return results;

        }

        return ans;
     */
     
    }

    /**
     * Examines a set of resource records to see if any of them are an answer to the given question.
     *
     * @param rrs       The set of resource records to be examined
     * @param question  The DNS question
     * @return          true if the collection of resource records contains an answer to the given question.
     */
    private boolean containsAnswer(Collection<ResourceRecord> rrs, DNSQuestion question) {
        for (ResourceRecord rr : rrs) {
            if (rr.getQuestion().equals(question) && rr.getRecordType() == question.getRecordType()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds all the results for a specific question. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting resource records of the indicated type.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws DNSErrorException If the number CNAME redirection levels exceeds the value set in
     *                           maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getResultsFollowingCNames(DNSQuestion question, int maxIndirectionLevels)
            throws DNSErrorException {

        if (maxIndirectionLevels < 0) throw new DNSErrorException("CNAME indirection limit exceeded");

        Collection<ResourceRecord> directResults = iterativeQuery(question);
        if (containsAnswer(directResults, question)) {
          
            return directResults;
        }

        Set<ResourceRecord> newResults = new HashSet<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getResultsFollowingCNames(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Handles the process of sending an individual DNS query with a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     *
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     *
     * The method verbose.printQueryToSend() must be called every time a new query message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of all resource records
     * received in the response.
     * @throws DNSErrorException if the Rcode in the response is non-zero
     */
    public Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server)
            throws DNSErrorException {
        
        int attempts = 0;
        socket.connect(server,DEFAULT_DNS_PORT);
        
        DNSMessage query = buildQuery(question);
        DNSMessage response;
        byte[] buff = query.getUsed();
        byte[] buff2 = new byte[MAX_DNS_MESSAGE_LENGTH];
        DatagramPacket sendPacket = new DatagramPacket(buff, buff.length,server,DEFAULT_DNS_PORT);
        DatagramPacket receivePacket = new DatagramPacket(buff2, buff2.length);
        
        //need to check if message or response
        for (int i = 0; i < MAX_QUERY_ATTEMPTS; i++) {
            try {
                
                verbose.printQueryToSend("UDP", question, server, query.getID());
                socket.send(sendPacket);
                socket.receive(receivePacket);
                response = new DNSMessage(receivePacket.getData(), receivePacket.getLength());
                if (response.getID() == query.getID() && response.getQR()) { //check if received packet is response with correct id
                    break;
                
                } else {
                    continue;
                }
                } catch (SocketTimeoutException e) {
                    if (attempts < MAX_QUERY_ATTEMPTS) {
                        attempts++;
                        continue;
                    } else {
                        //timing out
                        return null;
                    }
                } catch (IOException e) {
                    throw new DNSErrorException("IO Exception");
                }
        }
        response = new DNSMessage(receivePacket.getData(), receivePacket.getLength());

        //check if message truncated
        
        if (false) { //false cause I couldn't get it to work
        
            try {
                verbose.printQueryToSend("TCP", question, server, query.getID());
                Socket socket = new Socket(server,DEFAULT_DNS_PORT);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader( new InputStreamReader(socket.getInputStream()));
                out.println(query.getUsed());
                
                
                byte[] respond = new byte[MAX_DNS_MESSAGE_LENGTH];
                int bytes = in.read();
                for(int i = 0; i < bytes ; i++) {
                    byte[] temp = new byte[respond.length + 2];
                    System.arraycopy(respond, 0, temp, 0, respond.length);
                    temp[temp.length - 2] = (byte) in.read();
                    respond = temp;
                }
                buff2 = respond;
                

                socket.close();
            } catch (IOException e) {
                throw new DNSErrorException("tcp connection failure");
            }
            
            
            response = new DNSMessage(buff2, buff2.length);
        }
       
            
            
            if (response.getRcode() != 0) {
                throw new DNSErrorException("Rcode value not zero");
            } else if(response.getQR() && (query.getID() == response.getID())) {
                
                try {
                    Set<ResourceRecord> rr = processResponse(response);
                     //responses are returning
                    return rr;
                } catch (DNSErrorException e) {
                    throw new DNSErrorException("error Rcode");
                } catch (DNSReplyTruncatedException e) {
                    throw new DNSErrorException("error truncate");
                }

            } else {
                
                return null;
            }
            
        

        
       
    }

    /**
     * Creates a DNSMessage containing a DNS query.
     * A random transaction ID must be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the message's buffer's position (`message.buffer.position`) must be equivalent
     * to the size of the query data.
     *
     * @param question    Host name and record type/class to be used for the query.
     * @return The DNSMessage containing the query.
     */
    public DNSMessage buildQuery(DNSQuestion question) {
        /* TODO: To be implemented by the student */
        DNSMessage message = new DNSMessage((short)random.nextInt()); //setup header for dns question query and set buffer position to start of data
        message.addQuestion(question);
        
        return message;
    }

    /**
     * Parses and processes a response received by a nameserver.
     *
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     *
     * If the message has been truncated (the TC bit in the header is 1) then ignores the content of the message and
     * throws a DNSReplyTruncatedException.
     *
     * Adds all resource records found in the response message to the cache.
     * Calls methods in the verbose object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param message The DNSMessage received from the server.
     * @return A set of all resource records received in the response.
     * @throws DNSErrorException if the Rcode value in the reply header is non-zero
     * @throws DNSReplyTruncatedException if the TC bit is 1 in the reply header
     */
    public Set<ResourceRecord> processResponse(DNSMessage message) throws DNSErrorException, DNSReplyTruncatedException {
        /* TODO: To be implemented by the student */
        HashSet<ResourceRecord> rr = new HashSet<ResourceRecord>();


        if (message.getRcode() != 0) {
            throw new DNSErrorException("Error: non zero Rcode value");
        } else if (message.getTC()) {
            throw new DNSReplyTruncatedException("Error: truncated message");
        } else {
      
            for (int i = 0; i < message.getQDCount(); i++) {
                DNSQuestion question = message.getQuestion();
            }

            verbose.printResponseHeaderInfo(message.getID(), message.getAA(), message.getTC(), message.getRcode());
            verbose.printAnswersHeader(message.getANCount());

            
            for (int i = 0; i < message.getANCount(); i++) {
                ResourceRecord record = message.getRR();
                rr.add(record);
                cache.addResult(record);
                verbose.printIndividualResourceRecord(record,record.getRecordType().getCode(),record.getRecordClass().getCode());
            }

            verbose.printNameserversHeader(message.getNSCount());

            for (int i = 0; i < message.getNSCount(); i++) {
                ResourceRecord record = message.getRR();
                rr.add(record);
                cache.addResult(record);
                verbose.printIndividualResourceRecord(record,record.getRecordType().getCode(),record.getRecordClass().getCode());

            }

            verbose.printAdditionalInfoHeader(message.getARCount());
            for (int i = 0; i < message.getARCount(); i++) {
                ResourceRecord record = message.getRR();
                rr.add(record);
                cache.addResult(record);
                verbose.printIndividualResourceRecord(record,record.getRecordType().getCode(),record.getRecordClass().getCode());

            }

            

            
        }
        return rr;
    }

    public static class DNSErrorException extends Exception {
        public DNSErrorException(String msg) {
            super(msg);
        }
    }

    public static class DNSReplyTruncatedException extends Exception {
        public DNSReplyTruncatedException(String msg) {
            super(msg);
        }
    }
}
