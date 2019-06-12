/**
 * ********************************************************************
 * Jhove - JSTOR/Harvard Object Validation Environment
 * Copyright 2004 by JSTOR and the President and Fellows of Harvard College
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *********************************************************************
 */
package org.ithaka.portico.jhove.module;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.text.MessageFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import org.ithaka.portico.jhove.module.tar.MessageConstants;

import com.ice.tar.InvalidHeaderException;
import com.ice.tar.TarEntry;
import com.ice.tar.TarInputStream;

import edu.harvard.hul.ois.jhove.Agent;
import edu.harvard.hul.ois.jhove.Agent.Builder;
import edu.harvard.hul.ois.jhove.AgentType;
import edu.harvard.hul.ois.jhove.Checksum;
import edu.harvard.hul.ois.jhove.ChecksumType;
import edu.harvard.hul.ois.jhove.Checksummer;
import edu.harvard.hul.ois.jhove.Document;
import edu.harvard.hul.ois.jhove.DocumentType;
import edu.harvard.hul.ois.jhove.ErrorMessage;
import edu.harvard.hul.ois.jhove.ExternalSignature;
import edu.harvard.hul.ois.jhove.Identifier;
import edu.harvard.hul.ois.jhove.IdentifierType;
import edu.harvard.hul.ois.jhove.ModuleBase;
import edu.harvard.hul.ois.jhove.Property;
import edu.harvard.hul.ois.jhove.PropertyArity;
import edu.harvard.hul.ois.jhove.PropertyType;
import edu.harvard.hul.ois.jhove.RepInfo;
import edu.harvard.hul.ois.jhove.Signature;
import edu.harvard.hul.ois.jhove.SignatureType;
import edu.harvard.hul.ois.jhove.SignatureUseType;

/**
 * Module for identification and validation of TAR files.
 *
 * @author Michael C. Maggio
 * @author Karen Hanson
 */
public class TarModule extends ModuleBase {

    private static final Logger LOGGER = Logger.getLogger(TarModule.class.getName());

    /**
     * ****************************************************************
     * PRIVATE CLASS FIELDS.
     * ****************************************************************
     */
    private static final String NAME = "TAR-ptc";
    private static final String RELEASE = "1.2";
    private static final int[] DATE = {2011, 06, 06};
    private static final String RIGHTS_YEAR = "2011";
    private static final String[] FORMAT = {"TAR"};
    private static final String COVERAGE = "TAR";
    private static final String[] MIMETYPE = {"application/x-tar"};
    private static final String WELLFORMED = null;
    private static final String VALIDITY = null;
    private static final String REPINFO = null;
    private static final String NOTE = "This module uses a Portico-modified javagnutar com.ice.tar for testing of TAR files.";

    // TAR agent information
    private static final String TAR_AGENTNAME = "GNU";
    private static final AgentType TAR_AGENTTYPE = AgentType.NONPROFIT;
    private static final String TAR_AGENTADDRESS = "Free Software Foundation, 51 Franklin Street, Fifth Floor, "
            + " Boston, MA 02110-1301";
    private static final String TAR_AGENTWEBSITE = "http://www.gnu.org/";
    private static final String TAR_AGENTEMAIL = "membership@idpf.org";
    private static final String TAR_AGENTPHONE = "+1-617-542-5942";

    // formats
    private static final String TAR_FORMAT_USTAR = "ustar";
    private static final String TAR_FORMAT_V7 = "v7";
    private static final String TAR_FORMAT_GNU = "gnu";
    private static final String TAR_FORMAT_POSIX = "posix";
    private static final String TAR_FORMAT_STAR = "star";

    // compression type used in tar files - they are not compressed
    private static final String NO_COMPRESSION = "none";

    /* Checksummer object */
    private Checksummer _ckSummer;


    /* Top-level property list. */
    private List<Property> _propList;

    /* Top-level property. */
    private Property _metadata;

    /**
     * ****************************************************************
     * CLASS CONSTRUCTOR.
     * ****************************************************************
     */
    /**
     * Instantiate an <tt>TarModule</tt> object.
     */
    public TarModule() {
        super(NAME, RELEASE, DATE, FORMAT, COVERAGE, MIMETYPE, WELLFORMED,
                VALIDITY, REPINFO, NOTE, PorticoConstants.RIGHTS(RIGHTS_YEAR), false);

        initializeInstance(PorticoConstants.PORTICOVENDORNAME, PorticoConstants.PORTICOAGENTTYPE,
                PorticoConstants.PORTICOAGENTADDRESS, PorticoConstants.PORTICOAGENTTELEPHONE,
                PorticoConstants.PORTICOAGENTEMAIL);
    }

    /**
     * Multi-arg constructor for inheriting classes
     *
     * @param name
     * @param release
     * @param date
     * @param format
     * @param coverage
     * @param mimetype
     * @param wellformedNote
     * @param validityNote
     * @param repinfoNote
     * @param note
     * @param rights
     * @param isRandomAccess
     * @param agentName
     * @param agentType
     * @param agentAddress
     * @param agentTelephone
     * @param agentEmail
     */
    public TarModule(String name, String release, int[] date,
            String[] format, String coverage,
            String[] mimetype, String wellformedNote,
            String validityNote, String repinfoNote, String note,
            String rights, boolean isRandomAccess,
            String agentName, AgentType agentType,
            String agentAddress, String agentTelephone,
            String agentEmail) {
        super(name, release, date, format, coverage, mimetype, wellformedNote, validityNote, repinfoNote,
                note, rights, isRandomAccess);
        initializeInstance(agentName, agentType, agentAddress, agentTelephone, agentEmail);
    }

    /**
     * Convenience method for multi-arg constructors
     *
     * @param agentName
     * @param agentType
     * @param agentAddress
     * @param agentTelephone
     * @param agentEmail
     */
    protected void initializeInstance(String agentName, AgentType agentType,
            String agentAddress, String agentTelephone,
            String agentEmail) {

        Agent agent = new Builder(agentName, agentType)
                .address(agentAddress)
                .telephone(agentTelephone)
                .email(agentEmail).build();
        _vendor = agent;

        Agent formatDocAgent = new Builder(TAR_AGENTNAME, TAR_AGENTTYPE)
                .address(TAR_AGENTADDRESS)
                .telephone(TAR_AGENTPHONE)
                .web(TAR_AGENTWEBSITE)
                .email(TAR_AGENTEMAIL).build();

        Document doc = new Document("Tape Archive", DocumentType.REPORT);
        doc.setPublisher(formatDocAgent);
        doc.setDate("2001-01-01");
        doc.setIdentifier(new Identifier("http://www.gnu.org/software/tar/manual/html_node/index.html",
                IdentifierType.URL));
        _specification.add(doc);

        Signature sig = new ExternalSignature(".tar", SignatureType.EXTENSION,
                SignatureUseType.OPTIONAL);
        _signature.add(sig);
    }

    /**
     * Parse the content of a purported TAR file and store the results in
     * RepInfo.
     *
     * This uses the com.ice.tar package to loop through the TAR file entries.
     * Since the TAR file has no CRC, we have no way of knowing that the
     * contents of the TAR file is correct so long as we can read all the
     * headers. We also extend TarEntry with the inner class PtcTarEntry to
     * extract format information from the TAR header.
     *
     * @param stream An InputStream, positioned at its beginning, which is
     * generated from the object to be parsed. If multiple calls to
     * <code>parse</code> are made on the basis of a nonzero value being
     * returned, a new InputStream must be provided each time.
     *
     * @param info A fresh (on the first call) RepInfo object which will be
     * modified to reflect the results of the parsing If multiple calls to
     * <code>parse</code> are made on the basis of a nonzero value being
     * returned, the same RepInfo object should be passed with each call.
     *
     * @param parseIndex Must be 0 in first call to <code>parse</code>. If
     * <code>parse</code> returns a nonzero value, it must be called again with
     * <code>parseIndex</code> equal to that return value.
     * @return
     * @throws java.io.IOException
     */
    @Override
    public int parse(InputStream stream, RepInfo info, int parseIndex) throws IOException {
        // count number of entries in archive file
        long numEntries = 0;

        initParse();
        info.setModule(this);
        info.setFormat(_format[0]);
        info.setWellFormed(false);
        info.setValid(false);

        _ckSummer = null;
        if (_je != null && _je.getChecksumFlag()
                && info.getChecksum().size() == 0) {
            _ckSummer = new Checksummer();
        }

        _propList = new LinkedList<Property>();
        _metadata = new Property("TARMetadata",
                PropertyType.PROPERTY,
                PropertyArity.LIST,
                _propList);

        //Call tool and calculate stats
        try {
            String tarClass = TarInputStream.class.getName();
            String tarVersion = TarInputStream.CLASS_VERSION;
            LOGGER.fine("Extractor = " + tarClass);
            LOGGER.fine("Extractor = " + tarVersion);
            _propList.add(new Property("Extractor", PropertyType.STRING, tarClass));
            _propList.add(new Property("Version", PropertyType.STRING, tarVersion));

            File tempFile = null;
            tempFile = new File(info.getUri());
            if (!tempFile.exists()) {
                tempFile = new File(new URI(info.getUri()));
            }

            TarInputStream tis = null;
            String tarFormat = null;
            tis = new TarInputStream(new FileInputStream(tempFile));
            tis.setEntryFactory(new PtcTarEntryFactory());
            PtcTarEntry entry = null;
            try {
                // tar file is WFV if we can read the header for each entry
                while ((entry = (PtcTarEntry) tis.getNextEntry()) != null) {
                    numEntries++;
                    // get format from first entry
                    if (tarFormat == null) {
                        tarFormat = entry.getFormat();
                    }
                }
                // if we got here, then tar file is well formed
                info.setWellFormed(true);
                info.setValid(true);
                info.setVersion(tarFormat);
            } catch (InvalidHeaderException ih) {
                numEntries++;
                String msg = MessageFormat.format(MessageConstants.ERR_INVALID_HEADER_EXCEPTION, numEntries,
                        ih.getMessage());
                info.setMessage(new ErrorMessage(msg));
                info.setWellFormed(false);
            } catch (Exception e) {
                numEntries++;
                String msg = MessageFormat.format(MessageConstants.ERR_EXCEPTION, numEntries, e.getMessage());
                info.setMessage(new ErrorMessage(msg));
                info.setWellFormed(false);
                e.printStackTrace();
            } finally {
                // close input stream
                if (tis != null) {
                    try {
                        tis.close();
                    } catch (Exception e) {
                    }
                }
            }
        } catch (Exception f) {
            f.printStackTrace();
            info.setMessage(new ErrorMessage(f.getMessage()));
            info.setWellFormed(false);  // may not be the file's fault
            return 0;
        }

        // Check if user has aborted
        if (_je.getAbort()) {
            return 0;
        }

        // Take a deep breath.  We parsed it.  Now assemble the
        // properties.
        info.setProperty(_metadata);

        if (info.getWellFormed() == RepInfo.TRUE) {
            info.setMimeType(_mimeType[0]);

            // tar files are not compressed
            _propList.add(new Property("CompressionType", PropertyType.STRING, NO_COMPRESSION));

            // add number of entries
            _propList.add(new Property("EntryCount", PropertyType.LONG, numEntries));

            if (_ckSummer != null) {
                info.setChecksum(new Checksum(_ckSummer.getCRC32(),
                        ChecksumType.CRC32));
                String value = _ckSummer.getMD5();
                if (value != null) {
                    info.setChecksum(new Checksum(value, ChecksumType.MD5));
                }
                if ((value = _ckSummer.getSHA1()) != null) {
                    info.setChecksum(new Checksum(value, ChecksumType.SHA1));
                }
            }
        }

        return 0;
    }

    @Override
    protected void initParse() {
        super.initParse();
    }

    /**
     * A factory class for PtcTarEntry objects. Use this factory to return
     * PtcTarEntry objects instead of TarEntry objects when iterating through
     * Tar file entries.
     */
    public static class PtcTarEntryFactory
    implements TarInputStream.EntryFactory {

        @Override
        public TarEntry createEntry(String name) {
            return new PtcTarEntry(name);
        }

        @Override
        public TarEntry createEntry(File path)
                throws InvalidHeaderException {
            return new PtcTarEntry(path);
        }

        @Override
        public TarEntry createEntry(byte[] headerBuf)
                throws InvalidHeaderException {
            return new PtcTarEntry(headerBuf);
        }
    }

    /**
     * Represents a Tar file entry. We use this to class to derive the format of
     * the tar entry.
     */
    public static class PtcTarEntry extends TarEntry {

        private String format = null;

        public PtcTarEntry(String name) {
            super(name);
        }

        public PtcTarEntry(File path)
                throws InvalidHeaderException {
            super(path);
        }

        public PtcTarEntry(byte[] headerBuf)
                throws InvalidHeaderException {
            super(headerBuf);

            deriveFormat(headerBuf);
        }

        public String getFormat() {
            return format;
        }

        /**
         * Derives the format of this tar entry based on the header content.
         *
         * @param headerBuf Tar Header
         */
        private void deriveFormat(byte[] headerBuf) {
            if (this.getTarFormat() == UNIX_FORMAT) {
                // old unix v7 format
                format = TAR_FORMAT_V7;
            } else if (this.getTarFormat() == GNU_FORMAT) {
                // old and new gnu are indistinguishable from header
                format = TAR_FORMAT_GNU;
            } else if (this.getTarFormat() == USTAR_FORMAT) {
                // based on logic from GNU Tar, list.c: decode_header

                String starHdrPrefix = new String(headerBuf, 345, 131);
                String starHdrAtime = new String(headerBuf, 476, 12);
                String starHdrCtime = new String(headerBuf, 488, 12);

                byte typeflag = headerBuf[156];

                if (starHdrPrefix.charAt(130) == 0
                        && isOctal(starHdrAtime.charAt(0))
                        && starHdrAtime.charAt(11) == ' '
                        && isOctal(starHdrCtime.charAt(0))
                        && starHdrCtime.charAt(11) == ' ') {
                    format = TAR_FORMAT_STAR;
                } else if (typeflag == 'X' || typeflag == 'x') {
                    // POSIX.1-2001 type has extended header
                    format = TAR_FORMAT_POSIX;
                } else {
                    // good ol' POSIX.1-1988 format
                    format = TAR_FORMAT_USTAR;
                }
            } else {
            }
        }

        /**
         * Verifies if a character is between ASCII '0' and '7', inclusive
         * (octal). From GNU Tar, list.c: macro ISOCTAL().
         *
         * @param c Char to test
         * @return Boolean
         */
        private static boolean isOctal(char c) {
            return c >= '0' && c <= '7';
        }
    }
}
